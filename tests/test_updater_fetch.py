"""Non-regression tests for "omni-update.py fetch" (no network, temporary Git repositories).

The HTTPS remote accepted by the updater is redirected to a local bare repository
with Git's url.<base>.insteadOf mechanism, injected through GIT_CONFIG_* variables.
The production code path (URL validation, fetch, pinning, planning) is therefore
exercised unchanged, without any network access.
"""
import importlib.util
import os
from pathlib import Path
import subprocess

import pytest

SPEC = importlib.util.spec_from_file_location("omni_update_fetch", Path(__file__).resolve().parents[1] / "tools/omni-update.py")
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)

REMOTE = "https://git.example.invalid/omni/omnitech-siem-setup.git"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL,
                                   env={**os.environ, "LC_ALL": "C"}).decode().strip()


def commit(repo, name, text, message):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    """A working repository, its bare "GitHub" mirror and an installed checkout."""
    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "config", "user.name", "Fetch tests")
    git(work, "config", "user.email", "tests@example.invalid")
    base = commit(work, "mobile/soc/app.js", "const version = 1;\n", "base")
    mirror = tmp_path / "mirror.git"
    subprocess.check_call(["git", "clone", "-q", "--bare", str(work), str(mirror)])
    installed = tmp_path / "installed"
    subprocess.check_call(["git", "clone", "-q", str(mirror), str(installed)])
    newer = commit(work, "mobile/soc/app.js", "const version = 2;\n", "update")
    git(work, "push", "-q", str(mirror), "main")
    git(work, "tag", "v2")
    git(work, "push", "-q", str(mirror), "v2")
    # Redirect the HTTPS remote to the local mirror for every Git child process.
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.file://" + str(mirror) + ".insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", REMOTE)
    return {"work": work, "mirror": mirror, "installed": installed, "state": tmp_path / "state",
            "base": base, "newer": newer}


def test_fetch_downloads_a_pinned_candidate_and_keeps_checkout_untouched(upstream):
    installed, state = upstream["installed"], upstream["state"]
    result = updater.fetch(installed, state, REMOTE, "main")
    assert result["target"] == upstream["newer"]
    assert result["descends_from_installed"] is True
    assert result["installed_code_revision"] == upstream["base"]
    assert result["next"] == "plan --target " + upstream["newer"]
    # The installed checkout is never modified by fetch.
    assert git(installed, "rev-parse", "HEAD") == upstream["base"]
    assert (installed / "mobile/soc/app.js").read_text() == "const version = 1;\n"
    assert not (state / "update.lock").exists()
    cache = state / "repository.git"
    # Candidate and baseline are pinned: a later gc cannot break offline planning.
    assert git(cache, "rev-parse", "refs/omni/candidates/" + upstream["newer"]) == upstream["newer"]
    assert git(cache, "rev-parse", "refs/omni/base/" + upstream["base"]) == upstream["base"]
    git(cache, "gc", "-q", "--prune=now")
    plan = updater.plan(installed, state, upstream["newer"])
    assert plan["code_files"] == ["mobile/soc/app.js"]
    assert plan["can_apply_code"]


def test_fetch_of_a_tag_and_repeated_fetch_are_idempotent(upstream):
    installed, state = upstream["installed"], upstream["state"]
    first = updater.fetch(installed, state, REMOTE, "v2")
    second = updater.fetch(installed, state, REMOTE, "v2")
    assert first["target"] == second["target"] == upstream["newer"]


def test_missing_ref_is_reported_as_such_and_releases_the_lock(upstream):
    installed, state = upstream["installed"], upstream["state"]
    with pytest.raises(updater.UpdateError, match=r"fetch \(ref_not_found\)"):
        updater.fetch(installed, state, REMOTE, "branche-inexistante")
    assert not (state / "update.lock").exists()
    # A later valid fetch still works on the same cache.
    assert updater.fetch(installed, state, REMOTE, "main")["target"] == upstream["newer"]


def test_missing_repository_is_classified(upstream, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://git.example.invalid/other.git")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.file://" + str(upstream["mirror"]) + "-absent.insteadOf")
    with pytest.raises(updater.UpdateError, match=r"fetch \(repository_not_found\)"):
        updater.fetch(upstream["installed"], upstream["state"], "https://git.example.invalid/other.git", "main")
    assert not (upstream["state"] / "update.lock").exists()


@pytest.mark.parametrize("url", [
    "https://user:secret@git.example.invalid/repo.git",
    "https://token@git.example.invalid/repo.git",
    "https://git.example.invalid/repo.git?access_token=secret",
    "https://git.example.invalid/repo.git#fragment",
    "http://git.example.invalid/repo.git",
    "ssh://git@git.example.invalid/repo.git",
    "file:///tmp/repo.git",
    "/tmp/repo.git",
    "https://git.example.invalid/repo .git",
    "https://git.example.invalid:99999/repo.git",
])
def test_url_with_credentials_or_unsafe_scheme_is_refused_before_any_state(upstream, url):
    state = upstream["state"]
    with pytest.raises(updater.UpdateError, match="HTTPS"):
        updater.fetch(upstream["installed"], state, url, "main")
    assert not state.exists()


@pytest.mark.parametrize("ref", ["", "-main", "--upload-pack=evil", "a..b", "main.lock", "main/", "a//b",
                                 "refs/.hidden", "main@{1}", "main;id", "main branch"])
def test_malformed_ref_is_refused_before_any_state(upstream, ref):
    state = upstream["state"]
    with pytest.raises(updater.UpdateError, match="Invalid remote ref"):
        updater.fetch(upstream["installed"], state, REMOTE, ref)
    assert not state.exists()


def test_divergent_remote_is_fetched_but_flagged_and_refused_by_plan(upstream):
    work, installed, state = upstream["work"], upstream["installed"], upstream["state"]
    # Upstream history rewritten: the new main no longer contains the installed revision.
    git(work, "checkout", "-q", "--orphan", "rewritten")
    git(work, "rm", "-q", "-rf", ".")
    rewritten = commit(work, "mobile/soc/app.js", "const version = 3;\n", "rewritten history")
    git(work, "push", "-q", "-f", str(upstream["mirror"]), "rewritten:main")
    result = updater.fetch(installed, state, REMOTE, "main")
    assert result["target"] == rewritten
    assert result["descends_from_installed"] is False
    assert "divergent" in result["next"]
    with pytest.raises(updater.UpdateError, match="descend"):
        updater.plan(installed, state, rewritten)
    assert (installed / "mobile/soc/app.js").read_text() == "const version = 1;\n"


def test_unreachable_network_is_classified_without_leaking_output(upstream, monkeypatch):
    # Loopback port 1 refuses connections immediately: no external network involved.
    unreachable = "https://127.0.0.1:1/omni/repo.git"
    monkeypatch.delenv("GIT_CONFIG_COUNT")
    with pytest.raises(updater.UpdateError) as error:
        updater.fetch(upstream["installed"], upstream["state"], unreachable, "main", timeout=60)
    message = str(error.value)
    assert "network_unavailable" in message
    assert "127.0.0.1" not in message
    assert not (upstream["state"] / "update.lock").exists()


def test_fetch_timeout_is_reported_and_releases_the_lock(upstream, monkeypatch):
    real_run = subprocess.run

    def slow_run(argv, *args, **kwargs):
        if "fetch" in argv and REMOTE in argv:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(updater.subprocess, "run", slow_run)
    with pytest.raises(updater.UpdateError, match=r"network_unavailable: timeout"):
        updater.fetch(upstream["installed"], upstream["state"], REMOTE, "main", timeout=5)
    assert not (upstream["state"] / "update.lock").exists()


def test_concurrent_fetch_is_refused_by_the_lock(upstream):
    state = upstream["state"]
    state.mkdir()
    (state / "update.lock").write_text("12345")
    with pytest.raises(updater.UpdateError, match="already locked"):
        updater.fetch(upstream["installed"], state, REMOTE, "main")
    assert (state / "update.lock").read_text() == "12345"


def test_localized_git_messages_are_still_classified():
    assert updater.classify_git_error("fatal: couldn't find remote ref nope") == "ref_not_found"
    assert updater.classify_git_error("fatal: could not read Username for 'https://x': terminal prompts disabled") == "authentication_required"
    assert updater.classify_git_error("fatal: unable to access 'https://x/': Could not resolve host: x") == "network_unavailable"
    assert updater.classify_git_error("fatal: detected dubious ownership in repository at '/x'") == "unsafe_repository"
    assert updater.classify_git_error("something else") == "git_error"


def test_git_children_run_with_c_locale_and_no_prompt(monkeypatch, tmp_path):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    updater.git(tmp_path, "status")
    assert seen["LC_ALL"] == "C"
    assert seen["GIT_TERMINAL_PROMPT"] == "0"
