"""Mail importé de production : tests sans SMTP, GELF, réseau ni état réel."""
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = spec_from_loader(name, SourceFileLoader(name, str(ROOT / relative)))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def triage(monkeypatch):
    monkeypatch.setenv('OMNI_MAIL_LIB', str(ROOT / 'triage'))
    module = load('test_triage_v5', 'triage/omni-alert-triage')
    monkeypatch.setattr(module.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('réseau interdit'))
    monkeypatch.setattr(module.smtplib, 'SMTP', lambda *a, **k: pytest.fail('SMTP interdit'))
    return module


def test_site_links_use_configured_origin(triage, monkeypatch):
    monkeypatch.setattr(triage, 'env', lambda: {'OMNI_SOC_URL': 'https://siem.example.test/soc/'})
    assert triage.web_base() == 'https://siem.example.test'
    assert triage.replay_url({'replay_info': {'query': 'user:alice'}}).startswith('https://siem.example.test/search?')
    assert triage.web_base({'GRAYLOG_WEB_URL': 'https://logs.example.test/graylog/'}) == 'https://logs.example.test/graylog'


def test_mail_requires_explicit_site_recipients(triage):
    with pytest.raises(ValueError, match='MAIL_RECIPIENTS'):
        triage.send_mail({}, {}, 'critical')


@pytest.mark.parametrize('title,tier,immediate,expected', [
    ('OMNI v5 - AD DCSync', 'CRITICAL', 'dcsync|leurre|canari', False),
    ('OMNI v5 - AD Compte leurre', 'CRITICAL', 'dcsync|leurre|canari', False),
    ('OMNI v5 - AD Fichier canari', 'CRITICAL', 'dcsync|leurre|canari', False),
    ('OMNI v5 - TI connexion C2', 'CRITICAL', 'dcsync|leurre|canari', True),
    ('OMNI v5 - AD DCSync', 'GRAY', 'dcsync', True),
    ('OMNI - Ransomware', 'CRITICAL', 'dcsync', False),
    ('OMNI v5 - AD DCSync', 'CRITICAL', '[', True),
])
def test_probation_policy_is_explicit(triage, monkeypatch, title, tier, immediate, expected):
    monkeypatch.setattr(triage.time, 'strftime', lambda *a: '2026-11-27')
    settings = {'OMNI_RODAGE_JUSQUA': '2026-12-04', 'OMNI_RODAGE_IMMEDIAT': immediate}
    assert bool(triage._rodage(settings, title, tier)) is expected


def test_probation_can_be_disabled_and_expires(triage, monkeypatch):
    assert triage._rodage({'OMNI_RODAGE': '0'}, 'OMNI v5 - AD test', 'GRAY') is None
    monkeypatch.setattr(triage.time, 'strftime', lambda *a: '2026-12-05')
    assert triage._rodage({'OMNI_RODAGE_JUSQUA': '2026-12-04'}, 'OMNI v5 - AD test', 'GRAY') is None


@pytest.fixture
def fp(monkeypatch, tmp_path):
    policy = tmp_path / 'fp.json'
    monkeypatch.setenv('OMNI_FP_V4_POLICY', str(policy))
    return load('test_site_fp_v4', 'triage/omni_fp_v4.py'), policy


def test_no_site_exception_by_default(fp):
    module, path = fp
    assert not path.exists()
    assert module.signature_message({'qname': 'example.com', 'src_ip': '192.0.2.1'}) is None


@pytest.mark.parametrize('policy', [[], {'schema': 2}, {'schema': 1, 'jvm_attach': []},
                                     {'schema': 1, 'pdf24_machine_tasks': 'true'},
                                     {'schema': 1, 'jvm_attach': {'PC': {'users': ['LAB\\build'], 'binary': 'java.exe'}}}])
def test_invalid_policy_cannot_suppress(fp, policy):
    module, path = fp
    path.write_text(json.dumps(policy))
    assert module.signature_message({'qname': 'example.com', 'src_ip': '192.0.2.1'}) is None


def test_dns_exception_is_scoped_to_explicit_client(fp):
    module, path = fp
    path.write_text(json.dumps({'schema': 1, 'urlhaus_dns_clients': ['192.0.2.1']}))
    matching = {'qname': 'example.com', 'src_ip': '192.0.2.1'}
    assert module.signature_alerte([matching], 1, True)['id'] == 'urlhaus_examplecom_dc'
    assert module.signature_alerte([matching], 2, True) is None
    assert module.signature_alerte([matching], 1, False) is None
    assert module.signature_alerte([matching, {'src_ip': '192.0.2.2'}], 2, True) is None


def test_jvm_exception_preserves_account_and_host_domains(fp):
    module, path = fp
    binary = r'C:\Program Files\ExampleJDK\bin\java.exe'
    path.write_text(json.dumps({'schema': 1, 'jvm_attach': {
        'build.lab.test': {'users': ['LAB\\build'], 'binary': binary}}}))
    event = {'event_id': '8', 'host': 'build.lab.test', module.W + 'SourceImage': binary,
             module.W + 'TargetImage': binary, module.W + 'SourceUser': 'LAB\\build'}
    assert module.signature_message(event)['id'] == 'injection_jvm_attach'
    assert module.signature_message(dict(event, host='build.other.test')) is None
    assert module.signature_message(dict(event, **{module.W + 'SourceUser': 'OTHER\\build'})) is None
    assert module.signature_message(dict(event, **{module.W + 'TargetImage': r'C:\Windows\System32\lsass.exe'})) is None


def test_kev_does_not_match_truncated_prefix(monkeypatch):
    module = load('test_kev_v5', 'triage/omni_v5_tri.py')
    monkeypatch.setattr(module, 'kev_map', lambda *a: {'BUILD-LAB-POSTE': {'cves': ['CVE-2026-0001']}})
    assert module.kev_machines(['BUILD-LAB-POSTE-OTHER']) == (None, None)
    assert module.kev_machines(['BUILD-LAB-POSTE'])[0] == 'BUILD-LAB-POSTE'


@pytest.fixture
def lot(monkeypatch, tmp_path):
    monkeypatch.setenv('OMNI_MAIL_LIB', str(ROOT / 'triage'))
    module = load('test_lot_v5', 'deploye/sbin/omni-alert-lot')
    module.LOT = str(tmp_path / 'lot.json')
    module.E = {'SMTP_FROM': 'siem@example.test', 'MAIL_RECIPIENTS': 'soc@example.test',
                'OMNI_SOC_URL': 'https://siem.example.test/soc/'}
    monkeypatch.setattr(module.smtplib, 'SMTP', lambda *a, **k: pytest.fail('SMTP interdit'))
    return module


def test_v3_dryrun_never_sends_or_consumes_queue(lot, monkeypatch):
    queue = Path(lot.LOT)
    queue.write_text(json.dumps([{'titre': 'OMNI - Test', 'score': 75, 't': 1795740000}]))
    before = queue.read_bytes()
    monkeypatch.setenv('LOT_DRYRUN', '1')
    assert lot.M3 is not None
    assert lot.main() == 0
    assert queue.read_bytes() == before


def test_missing_recipients_leave_queue_intact(lot):
    queue = Path(lot.LOT)
    queue.write_text('[{"titre":"Test"}]')
    before = queue.read_bytes()
    lot.E = {}
    assert lot.main() == 2
    assert queue.read_bytes() == before


def test_missing_queue_directory_is_empty(lot, tmp_path):
    lot.LOT = str(tmp_path / 'not-installed' / 'lot.json')
    assert lot.main() == 0
    assert not (tmp_path / 'not-installed').exists()
