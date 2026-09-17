"""
Tests for :mod:`port_service_host.active.tools`.

The builders are pure functions so that command lines can be asserted without
Docker, which matters here because several of these flags decide how much of the
network gets touched:

* naabu's own default scan type is CONNECT, so a SYN scan has to be asked for
  explicitly — a builder that "looks right" but omits ``-scan-type s`` would
  silently downgrade every scan;
* ``-exclude-cdn`` must be on for a general scan and off for the CDN probe (which
  already only looks at 80/443 and would otherwise lose nothing but meaning);
* ``--cap-add=NET_RAW`` is passed for SYN and for nothing else.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.asset_pipelines.port_service_host.active import tools
from service.recon_pipeline.asset_pipelines.port_service_host.active.tools import (
    NAABU_CONNECT,
    NAABU_SYN,
    TOP_PORTS_FULL,
    ToolImageMissingError,
    dnsx_a_args,
    dnsx_ptr_args,
    ensure_image,
    get_tool,
    httpx_probe_args,
    naabu_args,
    nmap_service_args,
    syn_looks_unavailable,
)

WORK = tools.WORKDIR


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def test_every_documented_tool_is_registered() -> None:
    for name in ("naabu", "nmap", "httpx", "dnsx"):
        assert get_tool(name).name == name


def test_unknown_tool_error_lists_known_names() -> None:
    with pytest.raises(KeyError, match="unknown tool"):
        get_tool("masscan")


# --------------------------------------------------------------------------- #
# Image preflight
# --------------------------------------------------------------------------- #


def test_ensure_image_explains_the_build_command(monkeypatch) -> None:
    monkeypatch.setattr(tools, "image_exists", lambda image: False)
    with pytest.raises(ToolImageMissingError) as excinfo:
        ensure_image()
    message = str(excinfo.value)
    assert "docker build -t port_service_host_image" in message
    assert "port_service_host" in message


def test_ensure_image_is_silent_when_the_image_exists(monkeypatch) -> None:
    monkeypatch.setattr(tools, "image_exists", lambda image: True)
    ensure_image()


# --------------------------------------------------------------------------- #
# run_tool
# --------------------------------------------------------------------------- #


class CapturingRunner:
    """Captures the kwargs ``run_tool`` would hand to ``docker run``."""

    def __init__(self):
        self.kwargs: dict[str, object] = {}
        self.args: list[str] = []
        self.image = ""

    def __call__(self, **kwargs):
        self.kwargs = kwargs
        self.args = list(kwargs["args"])
        self.image = kwargs["image"]
        return kwargs


def test_run_tool_prefixes_the_binary_and_mounts_the_output_dir(tmp_path, monkeypatch) -> None:
    captured = CapturingRunner()
    monkeypatch.setattr(tools, "run_container", captured)
    monkeypatch.setattr(tools, "require_docker", lambda: None)
    monkeypatch.setattr(tools, "image_exists", lambda image: True)

    tools.run_tool("naabu", ["-p", "80"], output_dir=tmp_path, suffix="-x")

    assert captured.args[0] == "naabu"
    assert captured.args[1:] == ["-p", "80"]
    assert captured.kwargs["volumes"] == [(tmp_path, WORK, "rw")]
    assert captured.kwargs["name"] == "psh-naabu-x"
    assert captured.kwargs["cap_add"] is None


def test_run_tool_passes_capabilities_only_when_asked(tmp_path, monkeypatch) -> None:
    captured = CapturingRunner()
    monkeypatch.setattr(tools, "run_container", captured)
    monkeypatch.setattr(tools, "require_docker", lambda: None)
    monkeypatch.setattr(tools, "image_exists", lambda image: True)

    tools.run_tool("naabu", [], output_dir=tmp_path, cap_add=[tools.CAP_NET_RAW])
    assert captured.kwargs["cap_add"] == [tools.CAP_NET_RAW]


# --------------------------------------------------------------------------- #
# naabu arguments
# --------------------------------------------------------------------------- #


def test_naabu_args_uses_the_top_n_preset_by_default() -> None:
    args = naabu_args()
    assert args[:2] == ["-list", f"{WORK}/tool-input.txt"]
    assert "-top-ports" in args
    assert args[args.index("-top-ports") + 1] == "1000"
    assert "-p" not in args


def test_naabu_args_uses_the_full_preset_for_l3() -> None:
    args = naabu_args(top_ports=TOP_PORTS_FULL)
    assert args[args.index("-top-ports") + 1] == "full"


def test_naabu_args_accepts_an_explicit_port_list_instead_of_a_preset() -> None:
    args = naabu_args(ports=[80, 443], top_ports="1000")
    assert args[args.index("-p") + 1] == "80,443"
    assert "-top-ports" not in args


def test_naabu_args_is_explicit_about_the_scan_type() -> None:
    """naabu's own default is CONNECT, so SYN must be requested."""
    assert naabu_args(scan_type=NAABU_SYN)[naabu_args(scan_type=NAABU_SYN).index("-scan-type") + 1] == "s"
    assert (
        naabu_args(scan_type=NAABU_CONNECT)[
            naabu_args(scan_type=NAABU_CONNECT).index("-scan-type") + 1
        ]
        == "c"
    )


def test_naabu_args_carries_the_rate_and_retry_budget() -> None:
    args = naabu_args(rate=250, retries=3)
    assert args[args.index("-rate") + 1] == "250"
    assert args[args.index("-retries") + 1] == "3"


def test_naabu_args_skips_host_discovery_by_default() -> None:
    assert "-Pn" in naabu_args()


def test_naabu_args_only_excludes_cdn_when_asked() -> None:
    assert "-exclude-cdn" not in naabu_args()
    assert "-exclude-cdn" in naabu_args(exclude_cdn=True)
    # The CDN display flag is always on: it costs nothing and adds corroboration.
    assert "-cdn" in naabu_args()


def test_naabu_args_passes_resolvers_and_ip_version_when_given() -> None:
    args = naabu_args(resolvers=f"{WORK}/resolvers.txt", ip_version="4,6")
    assert args[args.index("-r") + 1] == f"{WORK}/resolvers.txt"
    assert args[args.index("-iv") + 1] == "4,6"


# --------------------------------------------------------------------------- #
# nmap arguments
# --------------------------------------------------------------------------- #


def test_nmap_args_writes_xml_to_a_file_not_stdout() -> None:
    """``-oX -`` would interleave nmap's report with the document."""
    args = nmap_service_args(["1.1.1.1"], ports=[8080], xml_path=f"{WORK}/nmap-1.xml")
    assert args[args.index("-oX") + 1] == f"{WORK}/nmap-1.xml"
    assert "-" not in args[args.index("-oX") + 1 : args.index("-oX") + 2]


def test_nmap_args_confines_the_probe_to_the_given_ports() -> None:
    args = nmap_service_args(["1.1.1.1"], ports=[8443, 8080, 8080], xml_path=f"{WORK}/x.xml")
    assert args[args.index("-p") + 1] == "8080,8443"


def test_nmap_args_defaults_to_low_intensity_and_no_dns() -> None:
    args = nmap_service_args(["1.1.1.1"], ports=[8080], xml_path=f"{WORK}/x.xml")
    assert "--version-light" in args
    assert "-Pn" in args and "-n" in args and "--open" in args
    assert "-sV" in args


def test_nmap_args_can_drop_the_light_preset_and_the_tls_script() -> None:
    args = nmap_service_args(
        ["1.1.1.1"], ports=[8080], xml_path=f"{WORK}/x.xml", version_light=False, tls_certs=False
    )
    assert "--version-light" not in args
    assert "--script" not in args


def test_nmap_args_rates_the_scan_when_told_to() -> None:
    args = nmap_service_args(["1.1.1.1"], ports=[1], xml_path=f"{WORK}/x.xml", max_rate=200)
    assert args[args.index("--max-rate") + 1] == "200"


# --------------------------------------------------------------------------- #
# httpx arguments
# --------------------------------------------------------------------------- #


def test_httpx_args_are_limited_to_the_two_web_ports() -> None:
    args = httpx_probe_args()
    assert args[args.index("-p") + 1] == "http:80,https:443"


def test_httpx_args_never_leave_the_random_agent_on() -> None:
    """The CLI's randomiser is on by default and emits impossible user agents."""
    assert "-random-agent=false" in httpx_probe_args()


def test_httpx_args_include_headers_so_a_waf_block_is_visible() -> None:
    assert "-irh" in httpx_probe_args()
    assert "-irh" not in httpx_probe_args(include_headers=False)


def test_dnsx_ptr_args_require_json_output() -> None:
    """The plain output echoes the input list, so only the JSON stream has names."""
    args = dnsx_ptr_args()
    assert "-json" in args and "-ptr" in args


def test_dnsx_a_args_ask_only_for_address_bearing_record_types() -> None:
    args = dnsx_a_args()
    assert "-a" in args and "-aaaa" in args and "-cname" in args
    assert "-ns" not in args and "-mx" not in args and "-txt" not in args


# --------------------------------------------------------------------------- #
# SYN degradation detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text",
    [
        "socket: operation not permitted",
        "CAP_NET_RAW capability is required",
        "permission denied",
        "unable to create raw socket",
    ],
)
def test_capability_shaped_failures_are_recognised(text: str) -> None:
    assert syn_looks_unavailable(text) is True


@pytest.mark.parametrize(
    "text",
    ["no route to host", "network is unreachable", "", "connection refused"],
)
def test_network_shaped_failures_are_not_mistaken_for_capabilities(text: str) -> None:
    """Degrading here would turn "the network said no" into a different scan."""
    assert syn_looks_unavailable(text) is False
