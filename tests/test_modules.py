"""Contrat de module (docs/MODULES.md) : manifestes, activation par site, cycle de vie, à blanc, sans réseau."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from omni_integrations import modules as mod  # noqa: E402
from omni_integrations.core import build_pack, digest, load_module  # noqa: E402
from omni_integrations.socle import load_site_profile  # noqa: E402

PROFILES = ROOT / "integrations" / "profiles"
MULTISITE = PROFILES / "site-multisite-fortigate-eset.example.json"
PME = PROFILES / "site-pme-watchguard.example.json"


def _secret(root, relative="etc/omni-siem/secrets/fortigate/dhcp_api"):
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("fictif\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


# ----------------------------------------------------------------------------- manifestes
def test_every_manifest_satisfies_the_contract():
    result = mod.validate_all()
    assert result["problems"] == []
    ids = {m["id"] for m in result["modules"]}
    assert {"watchguard", "fortigate", "eset"} <= ids


@pytest.mark.parametrize("module_id", mod.module_ids(), ids=str)
def test_fields_used_by_capabilities_are_produced(module_id):
    module, caps = mod.load_manifest(module_id), mod.capabilities()
    fields, prefixes = mod.module_fields(module), set(module["field_prefixes"])
    for source in module["provides"]["sources"]:
        for field in caps["sources"][source].get("fields", []):
            assert mod.field_known(field, fields, prefixes), (module_id, field)
        # La source est rattachée à son module : le socle SOC l'active avec le module.
        spec = caps["sources"][source]
        assert spec.get("module") == module_id or spec.get("integration") == module_id


@pytest.mark.parametrize("module_id", mod.module_ids(), ids=str)
def test_collector_units_are_conditioned_and_secret_free(module_id):
    module = mod.load_manifest(module_id)
    pairs = mod.parse_deploy_manifest(ROOT)
    for collector in module["collectors"]:
        text = (ROOT / pairs["/etc/systemd/system/" + collector["unit"]]).read_text(encoding="utf-8")
        assert mod.unit_condition_problems(text, module_id, collector["unit"]) == []


def test_unconditioned_unit_and_literal_secret_are_refused():
    assert mod.unit_condition_problems("[Unit]\nDescription=x\n[Service]\nExecStart=/bin/true\n", "demo")
    assert mod.unit_condition_problems("[Unit]\nConditionPathExists=|/etc/omni-siem/modules.d/demo.enabled\n"
                                       "ConditionPathExists=|!/etc/omni-siem/modules.d\n[Service]\n"
                                       "Environment=API_TOKEN=abc\n", "demo")
    module = copy.deepcopy(mod.load_manifest("fortigate"))
    module["secrets"][0]["value"] = "x"
    module["site_config"]["schema"]["dhcp_host"]["default"] = "ghp_" + "A" * 36
    problems = mod.validate_manifest(module, all_ids=mod.module_ids())
    assert any("valeur écrite" in p for p in problems)
    assert any("secret en clair" in p for p in problems)
    assert all("ghp_" not in p for p in problems)  # la valeur n'est jamais recopiée


def test_contract_defects_are_reported():
    module = copy.deepcopy(mod.load_manifest("eset"))
    module["fields"] = []
    module["field_prefixes"] = []
    module["checks"] = [{"id": "x", "type": "inconnu"}]
    module["depends"] = ["absent"]
    module["secrets"] = [{"name": "api", "default_path": "/tmp/api"}]
    problems = " | ".join(mod.validate_manifest(module, all_ids=mod.module_ids()))
    for expected in ("déclarer ses champs", "type inconnu", "module inconnu", "default_path", "eset_threat_name"):
        assert expected in problems


def test_legacy_scripts_carry_the_activation_gate():
    for module_id in ("fortigate", "eset"):
        module = mod.load_manifest(module_id)
        assert module["status"] == "legacy"
        for script in module["legacy"]["scripts"]:
            assert f"omni_module_enabled {module_id}" in (ROOT / script).read_text(encoding="utf-8")


def test_watchguard_v2_metadata_keeps_the_content_pack_identical():
    module = load_module("watchguard")
    assert module["schema_version"] == 2 and module["revision"] == 4
    reduced = {k: v for k, v in module.items() if k not in
               ("summary", "compat", "depends", "provides", "site_config", "inputs", "checks", "rollback", "uninstall")}
    reduced["schema_version"] = 1
    assert digest(build_pack(module)) == digest(build_pack(reduced))


def test_dependency_cycle_is_detected():
    mods = {"a": {"depends": ["b"]}, "b": {"depends": ["a"]}}
    assert mod.dependency_cycles(mods)


# ----------------------------------------------------------------------------- shell
def test_shell_gate(tmp_path):
    script = f'source "{ROOT}/lib-modules.sh"; omni_module_enabled "$1" && echo oui || echo non'
    env = dict(os.environ, OMNI_MODULES_DIR=str(tmp_path / "modules.d"))
    run = lambda mid: subprocess.run(["bash", "-c", script, "-", mid], env=env, capture_output=True,  # noqa: E731
                                     text=True, check=True).stdout.strip()
    assert run("fortigate") == "oui"          # site historique : tout reste actif
    (tmp_path / "modules.d").mkdir()
    assert run("fortigate") == "non"
    (tmp_path / "modules.d" / "fortigate.enabled").write_text("{}", encoding="utf-8")
    assert run("fortigate") == "oui" and run("eset") == "non"
    assert run("../etc") == "non"


# ----------------------------------------------------------------------------- profils et cycle de vie
def test_legacy_site_keeps_every_module_and_writes_nothing(tmp_path):
    site = tmp_path / "integrations.json"
    site.write_text('{"schema_version": 1}', encoding="utf-8")
    report = mod.apply(site, root=tmp_path / "root", apply=True)
    assert report["legacy"] and report["changes"] == []
    assert set(report["enabled"]) == set(mod.module_ids())
    assert not (tmp_path / "root" / "etc/omni-siem/modules.d").exists()


def test_pme_profile_dry_run_installs_only_watchguard(tmp_path):
    root = tmp_path / "root"
    report = mod.plan(PME, root=root)
    actions = {m["id"]: m for m in report["modules"]}
    assert report["blockers"] == []
    assert report["enabled"] == ["watchguard"]
    assert actions["watchguard"]["action"] == "activer"
    assert actions["fortigate"]["action"] == actions["eset"]["action"] == "inactif"
    assert "/usr/local/sbin/omni-fortidhcp-fetch" in actions["fortigate"]["files_skipped"]
    assert actions["fortigate"]["timers_enable"] == [] and actions["fortigate"]["graylog"] == {}
    assert "fortigate" not in report["effective_sources"] and "watchguard" in report["effective_sources"]
    applied = mod.apply(PME, root=root, apply=True, runner=mod.Runner(simulate=True))
    markers = sorted(p.name for p in (root / "etc/omni-siem/modules.d").iterdir())
    assert markers == ["watchguard.enabled"] and applied["transaction"]


def test_multisite_profile_requires_its_secret_then_installs_fortigate_and_eset(tmp_path):
    root = tmp_path / "root"
    blocked = mod.plan(MULTISITE, root=root)
    assert any("dhcp_api" in b for b in blocked["blockers"])
    refused = mod.apply(MULTISITE, root=root, apply=True)
    assert refused.get("refused") and not (root / "etc/omni-siem/modules.d").exists()
    _secret(root)
    report = mod.plan(MULTISITE, root=root)
    assert report["blockers"] == [] and report["enabled"] == ["eset", "fortigate"]
    forti = next(m for m in report["modules"] if m["id"] == "fortigate")
    assert forti["timers_enable"] == ["omni-fortidhcp-fetch.timer"]
    assert forti["parameters"]["dhcp_host"] == "192.0.2.1" and forti["secrets"]["dhcp_api"]["state"] == "ok"
    assert {"fortigate", "eset", "m365"} <= set(report["effective_sources"])
    assert "watchguard" not in report["enabled"]


def test_secret_with_open_permissions_is_refused(tmp_path):
    root = tmp_path / "root"
    os.chmod(_secret(root), 0o644)
    assert any("droits trop ouverts" in b for b in mod.plan(MULTISITE, root=root)["blockers"])


def test_apply_upgrade_and_rollback(tmp_path):
    root, state = tmp_path / "root", tmp_path / "state"
    _secret(root)
    unit = root / "etc/systemd/system/omni-fortidhcp-fetch.timer"
    unit.parent.mkdir(parents=True)
    unit.write_text("[Timer]\n", encoding="utf-8")
    runner = mod.Runner(simulate=True)
    first = mod.apply(MULTISITE, root=root, state_dir=state, apply=True, runner=runner)
    assert ["systemctl", "enable", "--now", "omni-fortidhcp-fetch.timer"] in runner.calls
    assert mod.plan(MULTISITE, root=root)["modules"][1]["action"] in ("à jour",)
    # Mise à niveau : la révision du marqueur diffère de celle du manifeste.
    marker = root / "etc/omni-siem/modules.d/fortigate.enabled"
    data = json.loads(marker.read_text(encoding="utf-8"))
    data["revision"] = 0
    marker.write_text(json.dumps(data), encoding="utf-8")
    forti = next(m for m in mod.plan(MULTISITE, root=root)["modules"] if m["id"] == "fortigate")
    assert forti["action"].startswith("mettre à niveau")
    second = mod.apply(MULTISITE, root=root, state_dir=state, apply=True, runner=runner)
    assert json.loads(marker.read_text(encoding="utf-8"))["revision"] == 1
    mod.rollback(second["transaction"], root=root, state_dir=state, apply=True, runner=runner)
    assert json.loads(marker.read_text(encoding="utf-8"))["revision"] == 0
    mod.rollback(first["transaction"], root=root, state_dir=state, apply=True, runner=runner)
    assert not (root / "etc/omni-siem/modules.d").exists()


def test_switching_profile_disables_and_uninstall_requires_site_change(tmp_path):
    root = tmp_path / "root"
    _secret(root)
    mod.apply(MULTISITE, root=root, apply=True)
    report = mod.plan(PME, root=root)
    actions = {m["id"]: m["action"] for m in report["modules"]}
    assert actions["fortigate"] == actions["eset"] == "désactiver" and actions["watchguard"] == "activer"
    with pytest.raises(mod.ModuleError):
        mod.uninstall("fortigate", MULTISITE, root=root)
    result = mod.uninstall("fortigate", PME, root=root, apply=True)
    assert result["keeps_data"] and not (root / "etc/omni-siem/modules.d/fortigate.enabled").exists()


def test_missing_required_parameter_and_unknown_module_block(tmp_path):
    site = tmp_path / "s.json"
    site.write_text(json.dumps({"schema_version": 1, "site": {"modules": ["inconnu"]}}), encoding="utf-8")
    with pytest.raises(mod.ModuleError):
        mod.plan(site, root=tmp_path)
    data = json.loads(MULTISITE.read_text(encoding="utf-8"))
    data["integrations"]["fortigate"]["parameters"]["dhcp_host"] = "bad host;rm"
    site.write_text(json.dumps(data), encoding="utf-8")
    assert any("motif" in b for b in mod.plan(site, root=tmp_path)["blockers"])


def test_verify_without_api_explains_instead_of_failing(tmp_path):
    root = tmp_path / "root"
    result = mod.verify(PME, root=root)
    states = {(r["module"], r["check"]): r["state"] for r in result["results"]}
    assert states[("fortigate", "-")] == "non configuré"
    assert states[("watchguard", "flux")].startswith("non vérifié")
    assert result["failures"] == 0


def test_socle_profile_enables_sources_of_active_modules():
    profile = load_site_profile(MULTISITE)
    assert {"fortigate", "eset"} <= set(profile["sources"])
    assert "watchguard" not in load_site_profile(MULTISITE)["sources"]
    assert "watchguard" in load_site_profile(PME)["sources"] and "eset" not in load_site_profile(PME)["sources"]


# ----------------------------------------------------------------------------- omni-deploy / omni-update / CLI
def test_deploy_engine_skips_files_of_inactive_modules(tmp_path):
    from omni_deploy.engine import Deployer
    root = tmp_path / "root"
    config = root / "etc/omni-siem/integrations.json"
    config.parent.mkdir(parents=True)

    def targets():
        deployer = Deployer(ROOT, home=ROOT, root=root)
        return {t for t, _, _ in deployer.entries(["robots", "systemd"])}, deployer
    shutil.copy(PME, config)
    listed, deployer = targets()
    assert "/usr/local/sbin/omni-fortidhcp-fetch" not in listed
    assert "/etc/systemd/system/omni-fortidhcp-fetch.service" not in listed
    assert {s["module"] for s in deployer.module_skipped} == {"fortigate"}
    # Un fichier déjà présent reste suivi (mis à jour, jamais supprimé) ; un site historique déploie tout.
    present = root / "usr/local/sbin/omni-fortidhcp-fetch"
    present.parent.mkdir(parents=True)
    present.write_text("ancien", encoding="utf-8")
    assert "/usr/local/sbin/omni-fortidhcp-fetch" in targets()[0]
    config.write_text('{"schema_version": 1}', encoding="utf-8")
    assert "/etc/systemd/system/omni-fortidhcp-fetch.service" in targets()[0]


def test_manifest_revision_helper():
    assert mod.manifest_revision(b'{"revision": 3}') == 3
    assert mod.manifest_revision(None) is None and mod.manifest_revision(b"x") is None


def test_cli_plan_and_validate(tmp_path):
    cli = [sys.executable, str(ROOT / "tools/omni-integrations.py"), "modules"]
    out = subprocess.run(cli + ["plan", "--site-config", str(PME), "--root", str(tmp_path)],
                         capture_output=True, text=True, check=True).stdout
    assert json.loads(out)["enabled"] == ["watchguard"]
    assert subprocess.run(cli + ["validate"], capture_output=True, text=True).returncode == 0
    refused = subprocess.run(cli + ["plan", "--apply", "--site-config", str(PME)], capture_output=True, text=True)
    assert refused.returncode != 0
