import os
import subprocess
from pathlib import Path

from service.recon_pipeline.asset_pipelines.config import TARGET

IMAGE = "projectdiscovery/chaos-client:latest"

# Loaded from .env (set in project root). Hardcoding the key here is wrong -
# it leaks into version control and makes rotation painful.
CHAOS_KEY = os.getenv("CHAOS_KEY")
if not CHAOS_KEY:
    raise ValueError(
        "CHAOS_KEY is not set in .env. Add it to the project root .env file "
        "(see service/recon_pipeline/asset_pipelines/subdomain_domain_wildcards/passive/README.md)."
    )

# Output always lands in passive/output, regardless of cwd
OUTPUT_DIR = Path(__file__).resolve().parent / "output"
OUTPUT_FILE = OUTPUT_DIR / "chaos.txt"


def run(domain: str = TARGET) -> Path:
    """Run chaos passive enum via Docker; write results to passive/output/chaos.txt."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        "docker", "run", "--rm",
        IMAGE,
        "-d", domain,
        "-key", CHAOS_KEY,
        "-silent",
    ]

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        subprocess.run(
            cmd,
            stdout=file,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

    return OUTPUT_FILE


if __name__ == "__main__":
    run()
    print(f"Chaos results saved to: {OUTPUT_FILE}")
