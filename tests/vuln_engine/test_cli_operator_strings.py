"""Item 2.6 — operator strings that ride protocol boundaries are checked.

``--cookie``/``--session-b-cookie`` become a raw ``Cookie`` header value and
the collaborator URLs become payload URL bases, so a CR or LF in any of them
is header injection against our own transport. The CLI refuses at parse time,
before anything is wired. The safe controls prove the check is about the
dangerous characters, not about cookies in general.
"""

from __future__ import annotations

import pytest

import run_engine


def test_a_cookie_with_a_newline_is_refused(capsys) -> None:
    code = run_engine.main(["-t", "example.test", "--cookie", "sid=abc\r\nX-Foo: 1"])
    assert code == 2
    err = capsys.readouterr().err
    assert "header injection" in err
    assert "session-b-cookie" not in err or "cookie" in err


def test_a_session_b_cookie_with_a_carriage_return_is_refused(capsys) -> None:
    code = run_engine.main(
        ["-t", "example.test", "--session-b-cookie", "sid=abc\rX-Foo: 1"]
    )
    assert code == 2
    assert "header injection" in capsys.readouterr().err


def test_a_non_latin1_cookie_value_is_refused(capsys) -> None:
    # '€' is U+20AC: outside latin-1, which is what a header value must be.
    code = run_engine.main(["-t", "example.test", "--cookie", "sid=5€"])
    assert code == 2
    assert "latin-1" in capsys.readouterr().err


def test_a_cookie_without_an_equals_is_refused(capsys) -> None:
    code = run_engine.main(["-t", "example.test", "--cookie", "just-a-name"])
    assert code == 2
    assert "NAME=VALUE" in capsys.readouterr().err


def test_a_collaborator_url_with_a_control_character_is_refused(capsys) -> None:
    code = run_engine.main(
        ["-t", "example.test", "--collaborator-url", "http://oob\n.evil.test"]
    )
    assert code == 2
    assert "collaborator-url" in capsys.readouterr().err


def test_a_collaborator_local_with_a_control_character_is_refused(capsys) -> None:
    code = run_engine.main(
        ["-t", "example.test", "--collaborator-local", "http://127.0.0.1:9009\r"]
    )
    assert code == 2
    assert "collaborator-local" in capsys.readouterr().err


def test_an_output_dir_with_a_control_character_is_refused(capsys) -> None:
    code = run_engine.main(["-t", "example.test", "--output-dir", "out\rdir"])
    assert code == 2
    assert "output-dir" in capsys.readouterr().err


def test_ordinary_cookies_and_urls_pass(monkeypatch, tmp_path) -> None:
    class _Reached(Exception):
        pass

    def _sentinel(*args: object, **kwargs: object) -> run_engine.RunReport:
        raise _Reached()

    monkeypatch.setattr(run_engine, "run", _sentinel)
    with pytest.raises(_Reached):
        run_engine.main(
            [
                "-t", "example.test",
                "--cookie", "sid=abc123",
                "--session-b-cookie", "sid=admin456",
                "--collaborator-url", "http://oob.example.test:9009",
                "--output-dir", str(tmp_path / "run"),
            ]
        )
