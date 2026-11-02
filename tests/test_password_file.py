# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The install script never prints a generated test-user password: it writes it to
demo/generated/<user>.password, created mode 0600, and prints only the path."""

import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import configure_iya_sts  # noqa: E402


def test_the_file_is_named_for_the_user_in_the_directory(tmp_path):
    assert configure_iya_sts.generated_file(tmp_path, "demo-user") == tmp_path / "demo-user.password"


def test_the_file_is_created_0600_from_the_start(tmp_path, monkeypatch):
    opened = []
    real_open = os.open

    def spy(path, flags, mode=0o777, *args, **kwargs):
        opened.append((Path(path).name, flags, mode))
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    target = configure_iya_sts.generated_file(tmp_path / "generated", "demo-user")
    previous = os.umask(0)
    try:
        configure_iya_sts.write_private(target, "s3cret-value")
    finally:
        os.umask(previous)
    assert opened == [("demo-user.password", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)]
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text(encoding="utf-8") == "s3cret-value\n"


def test_an_existing_wider_file_is_narrowed_to_0600(tmp_path):
    existing = tmp_path / "demo-user.password"
    existing.write_text("old\n", encoding="utf-8")
    existing.chmod(0o644)
    configure_iya_sts.write_private(existing, "new")
    assert stat.S_IMODE(existing.stat().st_mode) == 0o600
    assert existing.read_text(encoding="utf-8") == "new\n"


@pytest.mark.parametrize("username", ["", ".", "..", "a/b", "a\\b"])
def test_a_username_that_is_not_a_file_name_is_refused(tmp_path, username):
    with pytest.raises(ValueError):
        configure_iya_sts.generated_file(tmp_path, username)


def test_the_script_has_no_line_that_prints_a_generated_password():
    source = (ROOT / "scripts" / "configure_iya_sts.py").read_text(encoding="utf-8")
    assert "shown once" not in source
    for line in source.splitlines():
        if "print(" in line:
            assert "['password']" not in line and '["password"]' not in line, line
