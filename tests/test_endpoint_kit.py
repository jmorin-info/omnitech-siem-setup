"""Kit d'enrolement des postes : rendu, integrite et coherence avec le serveur, hors ligne.

Ces controles empechent le retour des defauts constates le 28/11/2026 :
fichiers adaptes a la main par site, marqueurs non remplaces, plage AD CS trop
courte, canal DNS analytique illisible, compteur d'audit dependant de la langue,
« test output » lance a chaque passage (RST cote SIEM), syntaxe PowerShell 7
dans un script qui doit tourner sous Windows PowerShell 5.1.
"""
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WINLOGBEAT = ROOT / "windows" / "winlogbeat.yml"
CORE = ROOT / "windows" / "Install-OmniSiem-NinjaOne.ps1"
WRAPPER = ROOT / "kit" / "install.ps1"
KIT_PS1 = [CORE, WRAPPER, ROOT / "windows" / "Get-OmniInventory.ps1"]
MARKER = re.compile(r"__[A-Z][A-Z0-9_]*__")
# Limite de l'API Windows Event Log : au-dela, « requete invalide » et le canal
# n'est plus lu du tout. Une plage compte pour deux conditions (>= et <=).
MAX_EVENT_CONDITIONS = 22
PWSH = shutil.which("pwsh")
OPENSSL = shutil.which("openssl")


def event_logs():
    return yaml.safe_load(WINLOGBEAT.read_text(encoding="utf-8"))["winlogbeat.event_logs"]


def parse_event_ids(spec):
    singles, ranges = [], []
    for item in str(spec).split(","):
        item = item.strip()
        if "-" in item:
            low, high = (int(x) for x in item.split("-"))
            ranges.append((low, high))
        else:
            singles.append(int(item))
    return singles, ranges


def security_ranges():
    sec = next(log for log in event_logs() if log["name"] == "Security")
    singles, ranges = parse_event_ids(sec["event_id"])
    return singles, ranges


def covered(event_id, singles, ranges):
    return event_id in singles or any(low <= event_id <= high for low, high in ranges)


# --- Configuration Winlogbeat -------------------------------------------------

def test_event_id_filters_stay_within_windows_query_limit():
    for log in event_logs():
        if "event_id" not in log:
            continue
        singles, ranges = parse_event_ids(log["event_id"])
        assert all(low < high for low, high in ranges), log["name"]
        conditions = len(singles) + 2 * len(ranges)
        assert conditions <= MAX_EVENT_CONDITIONS, f"{log['name']} : {conditions} conditions"


def test_security_ranges_cover_detection_needs():
    singles, ranges = security_ranges()
    # AD CS complet (4868-4900, dont 4898-4900 modeles), Kerberos, DS, NPS.
    for event_id in (1102, 4624, 4625, 4662, 4768, 4769, 4886, 4887, 4888, 4889,
                     4898, 4899, 4900, 5136, 5140, 5145, 6272, 6273, 7045):
        assert covered(event_id, singles, ranges), event_id
    # Les identifiants Security interpretes par le serveur sont tous collectes.
    with (ROOT / "lookups" / "win-events.csv").open(encoding="utf-8") as fh:
        server_ids = {int(row["event_id"]) for row in csv.DictReader(fh) if row["event_id"].isdigit()}
    missing = sorted(i for i in server_ids if 4600 <= i <= 6300 and not covered(i, singles, ranges))
    assert not missing, f"identifiants attendus par le serveur mais non collectes : {missing}"


def test_required_channels_present_and_unreadable_ones_absent():
    names = [log["name"] for log in event_logs()]
    assert len(names) == len(set(names)), "canal en double"
    for channel in ("Security", "System", "Microsoft-Windows-Sysmon/Operational", "Directory Service",
                    "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/MSI and Script",
                    "Microsoft-Windows-AppLocker/Packaged app-Execution",
                    "Microsoft-Windows-AppLocker/Packaged app-Deployment"):
        assert channel in names, channel
    # Canal analytique : Winlogbeat ne le lit pas (0 evenement) et l'activer
    # remplit un ETL de 1 Go sur le DC. Collecte DNS = ETW dedie.
    assert "Microsoft-Windows-DNSServer/Analytical" not in names
    assert all(log.get("api") != "wineventlog-experimental" for log in event_logs())
    ds = next(log for log in event_logs() if log["name"] == "Directory Service")
    assert "event_id" in ds, "Directory Service doit rester filtre (1535 a 1 000/h sinon)"


def test_ports_match_server_inputs_and_firewall():
    config = yaml.safe_load(WINLOGBEAT.read_text(encoding="utf-8"))
    assert config["output.logstash"]["hosts"] == ["__SIEM_FQDN__:5044"]
    assert '"port": 5044' in (ROOT / "07-inputs.sh").read_text(encoding="utf-8")
    firewall = (ROOT / "tools" / "render-firewall.py").read_text(encoding="utf-8")
    assert '"5044"' in firewall and '"1519"' in firewall
    assert "$BeatsPort       = 5044" in CORE.read_text(encoding="ascii")
    assert "5044, 443" in WRAPPER.read_text(encoding="ascii")
    assert re.search(r"^PORT=1519$", (ROOT / "kit" / "install.sh").read_text(encoding="utf-8"), re.M)
    assert "port:1519" in (ROOT / "92-linux.sh").read_text(encoding="utf-8")


# --- Scripts PowerShell -------------------------------------------------------

def test_powershell_kit_sources_are_ascii():
    # Servis sans BOM : Windows PowerShell 5.1 les lirait en ANSI.
    for path in KIT_PS1:
        path.read_bytes().decode("ascii")


def test_core_has_no_periodic_side_effects():
    core = CORE.read_text(encoding="ascii")
    assert "Register-ScheduledTask" in core and "-Force | Out-Null" not in core.split("Register-ScheduledTask", 1)[1][:400]
    # test output = diagnostic seulement, apres la recherche d'une connexion etablie.
    assert core.count("test output -c") == 1
    assert core.index("Get-NetTCPConnection") < core.index("test output -c")
    # journal Security : agrandi, jamais reduit ; audit lu par position de colonne.
    assert "MaximumSizeInBytes -lt $TargetBytes" in core
    assert "ussite" not in core and 'Select-String "Success' not in core
    assert "auditpol.exe /backup" in core
    # jamais de retour a une version plus ancienne de Winlogbeat
    assert "[version]$Installed -gt [version]$Target" in core


def _pwsh(script, *args):
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script, *args],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.skipif(not PWSH, reason="pwsh absent")
def test_powershell_parses_without_ps7_only_syntax():
    script = r"""
$bad = @()
foreach ($p in $args) {
  $tokens = $null; $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errors)
  foreach ($e in $errors) { $bad += "$p : $($e.Message)" }
  $ps7 = $ast.FindAll({ param($n)
      $n -is [System.Management.Automation.Language.TernaryExpressionAst] -or
      $n -is [System.Management.Automation.Language.PipelineChainAst] -or
      ($n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n.NullConditional) }, $true)
  foreach ($n in $ps7) { $bad += "$p : syntaxe PowerShell 7 ligne $($n.Extent.StartLineNumber)" }
  foreach ($t in $tokens) {
    if ($t.Kind -in 'QuestionQuestion', 'QuestionQuestionEquals', 'AndAnd', 'OrOr') {
      $bad += "$p : operateur PowerShell 7 ligne $($t.Extent.StartLineNumber)"
    }
  }
}
if ($bad.Count) { $bad; exit 1 }
"""
    _pwsh(script, *[str(p) for p in KIT_PS1])


@pytest.mark.skipif(not PWSH, reason="pwsh absent")
def test_audit_counter_is_language_independent():
    # Extraits reels de « auditpol /backup » sur Windows francais et anglais.
    french = [
        "Nom d'ordinateur,Cible de stratégie,Sous-catégorie,GUID de sous-catégorie,"
        "Paramètre d'inclusion,Paramètre d'exclusion,Valeur de paramètre",
        "PC1,Système,Pilote IPSEC,{0CCE9213-69AE-11D9-BED3-505054503030},Succès et échec,,3",
        "PC1,Système,Ouverture de session,{0CCE9215-69AE-11D9-BED3-505054503030},Succès,,1",
        "PC1,Système,Partage de fichiers,{0CCE9224-69AE-11D9-BED3-505054503030},Pas d'audit,,0",
        "PC1,,Option:CrashOnAuditFail,,Désactivé,,0",
    ]
    english = [
        "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value",
        "PC1,System,IPsec Driver,{0CCE9213-69AE-11D9-BED3-505054503030},Success and Failure,,3",
        "PC1,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Failure,,2",
        "PC1,System,File Share,{0CCE9224-69AE-11D9-BED3-505054503030},No Auditing,,0",
    ]
    script = r"""
$ast = [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$null, [ref]$null)
foreach ($name in 'ConvertFrom-OmniAuditBackup', 'Get-OmniBeatVersion') {
  $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
  . ([scriptblock]::Create($fn.Extent.Text))
}
$data = $args[1] | ConvertFrom-Json
@{ fr = (ConvertFrom-OmniAuditBackup ([string[]]$data.fr)); en = (ConvertFrom-OmniAuditBackup ([string[]]$data.en));
   v = (Get-OmniBeatVersion 'winlogbeat version 9.4.2 (amd64), libbeat 9.4.2 [e98b93d]') } | ConvertTo-Json -Compress
"""
    out = _pwsh(script, str(CORE), json.dumps({"fr": french, "en": english}))
    assert json.loads(out.strip().splitlines()[-1]) == {"fr": 2, "en": 2, "v": "9.4.2"}


# --- Publication du kit (95-kit-deploy.sh) ------------------------------------

@pytest.fixture
def site(tmp_path):
    if not OPENSSL:
        pytest.skip("openssl absent")
    key, crt = tmp_path / "beats.key", tmp_path / "beats.crt"
    subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=siem.example.test", "-keyout", str(key), "-out", str(crt)],
                   check=True, capture_output=True)
    kit = tmp_path / "siem-kit"
    (kit / "soar").mkdir(parents=True)
    (kit / "soar" / "blocklist.txt").write_text("192.0.2.66\n")
    (kit / "Sysmon64.exe").write_bytes(b"MZ binaire de test")
    (kit / "winlogbeat-oss-9.4.2-windows-x86_64.zip").write_bytes(b"PK archive de test")
    return {"tmp": tmp_path, "kit": kit, "crt": crt, "key": key}


def render(site, env_extra=None, **extra):
    values = {"SIEM_FQDN": "siem.example.test", "SIEM_IP": "192.0.2.10", "SITE_NAME": "site-test",
              "GRAYLOG_BEATS_CERT_FILE": str(site["crt"])}
    values.update(extra)
    vars_file = site["tmp"] / "00-vars.env"
    vars_file.write_text("".join(f'{k}="{v}"\n' for k, v in values.items()))
    env = dict(os.environ, KIT_DIR=str(site["kit"]), OMNI_VARS_FILE=str(vars_file), **(env_extra or {}))
    return subprocess.run(["bash", str(ROOT / "95-kit-deploy.sh")], env=env, capture_output=True, text=True, timeout=120)


def manifest(kit):
    entries = {}
    for line in (kit / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(None, 1)
        entries[name.lstrip("*")] = digest
    return entries


def test_rendered_kit_is_complete_verified_and_marker_free(site):
    result = render(site)
    assert result.returncode == 0, result.stdout + result.stderr
    kit = site["kit"]
    sums = manifest(kit)
    for name, digest in sums.items():
        assert hashlib.sha256((kit / name).read_bytes()).hexdigest() == digest, name
    for name in ("install.ps1", "Install-OmniSiem-NinjaOne.ps1", "agent.ps1", "winlogbeat.yml",
                 "omnitech-rootca.pem", "Sysmon64.exe", "winlogbeat-oss-9.4.2-windows-x86_64.zip"):
        assert name in sums, name
    for name in sums:
        if name.endswith((".ps1", ".sh", ".yml", ".csv", ".xml")):
            text = (kit / name).read_text(encoding="utf-8")
            assert not MARKER.search(text), f"marqueur restant dans {name}"
    config = yaml.safe_load((kit / "winlogbeat.yml").read_text(encoding="utf-8"))
    assert config["output.logstash"]["hosts"] == ["siem.example.test:5044"]
    assert config["output.logstash"]["ssl.certificate_authorities"] == ["C:/Program Files/Winlogbeat/omnitech-rootca.pem"]
    assert config["processors"][0]["add_fields"]["fields"]["site"] == "site-test"
    core = (kit / "Install-OmniSiem-NinjaOne.ps1").read_text(encoding="ascii")
    assert '$WinlogbeatVersion = "9.4.2"' in core
    assert '$AllowedBaseUrl  = "https://siem.example.test/kit"' in core
    assert '("0" -eq "1")' in core
    assert (kit / "agent.ps1").read_bytes() == (kit / "Install-OmniSiem-NinjaOne.ps1").read_bytes()
    assert (kit / "soar" / "blocklist.txt").read_text() == "192.0.2.66\n"
    assert list(site["tmp"].glob("siem-kit.previous.*")), "ancien kit non conserve"
    assert not list(site["tmp"].glob("siem-kit.stage.*"))


def test_site_specific_certificate_name_and_options(site):
    result = render(site, BEATS_CA_FILE="graylog-beats.pem", KIT_INSTALL_ROOT_CA="1", WINLOGBEAT_VERSION="8.19.7")
    assert result.returncode == 0, result.stdout + result.stderr
    kit = site["kit"]
    assert "graylog-beats.pem" in manifest(kit)
    config = yaml.safe_load((kit / "winlogbeat.yml").read_text(encoding="utf-8"))
    assert config["output.logstash"]["ssl.certificate_authorities"] == ["C:/Program Files/Winlogbeat/graylog-beats.pem"]
    core = (kit / "Install-OmniSiem-NinjaOne.ps1").read_text(encoding="ascii")
    assert '$BeatsCaName     = "graylog-beats.pem"' in core and '("1" -eq "1")' in core
    assert '$WinlogbeatVersion = "8.19.7"' in core
    assert "archive Winlogbeat 8.19.7 absente" in result.stderr


def test_private_key_is_never_published(site):
    bundle = site["tmp"] / "bundle.pem"
    bundle.write_text(site["crt"].read_text() + site["key"].read_text())
    result = render(site, GRAYLOG_BEATS_CERT_FILE=str(bundle))
    assert result.returncode != 0 and "clé privée" in result.stderr
    assert not (site["kit"] / "SHA256SUMS").exists()


def test_ambiguous_winlogbeat_version_is_refused(site):
    (site["kit"] / "winlogbeat-8.19.7-windows-x86_64.zip").write_bytes(b"PK autre archive")
    result = render(site)
    assert result.returncode != 0 and "WINLOGBEAT_VERSION" in result.stderr


def _fake_systemctl(site, rw_paths):
    """systemctl factice : un service en cours (omni-soar) avec ReadWritePaths donné ; journal des appels."""
    bindir = site["tmp"] / "bin"
    bindir.mkdir(exist_ok=True)
    calls = site["tmp"] / "systemctl.log"
    script = bindir / "systemctl"
    script.write_text(
        "#!/bin/bash\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$1" in\n'
        '  list-units) echo "omni-soar.service loaded active running SOAR"; echo "nginx.service loaded active running web";;\n'
        '  show) if [[ "$*" == *omni-soar.service* ]]; then echo "' + rw_paths + '"; else echo ""; fi;;\n'
        "esac\n"
        "exit 0\n")
    script.chmod(0o755)
    return bindir, calls


def test_publication_keeps_root_mode_and_restarts_writers(site):
    """28/11/2026 : la bascule imposait 755 (omni-geo-flux en échec) et laissait omni-soar
    écrire dans l'ancien répertoire monté (blocklist SOAR figée)."""
    kit = site["kit"]
    kit.chmod(0o775)
    bindir, calls = _fake_systemctl(site, f"/var/lib/omni-soar -{kit}/soar")
    result = render(site, env_extra={"PATH": f"{bindir}:{os.environ['PATH']}"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert (kit.stat().st_mode & 0o777) == 0o775
    log = calls.read_text()
    assert "try-restart omni-soar.service" in log
    assert "try-restart nginx.service" not in log
    assert "omni-soar.service relancé" in result.stdout


def test_publication_restart_can_be_disabled(site):
    bindir, calls = _fake_systemctl(site, f"{site['kit']}/soar")
    result = render(site, env_extra={"PATH": f"{bindir}:{os.environ['PATH']}", "KIT_RESTART_UNITS": "0"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert not calls.exists() or "try-restart" not in calls.read_text()


def test_kit_shell_scripts_parse():
    for script in ("95-kit-deploy.sh", "kit/install.sh", "kit/linux-omni.sh"):
        subprocess.run(["bash", "-n", str(ROOT / script)], check=True)
