#!/usr/bin/env bash
# Fresh, isolated Ubuntu 26.04 installation; no host provisioning or production access.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${OMNI_VM_REPORT:-$ROOT/ubuntu-vm-report.json}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/omni-ubuntu-vm.XXXXXXXX")"
VM_PID=""
STAGE=prerequisites
finish() {
  local code=$?
  trap - EXIT
  if [[ -n "$VM_PID" ]] && kill -0 "$VM_PID" 2>/dev/null; then
    kill "$VM_PID" 2>/dev/null || true
    wait "$VM_PID" 2>/dev/null || true
  fi
  if [[ ! -s "$REPORT" ]]; then
    python3 - "$REPORT" "$STAGE" "$code" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({"passed": False, "stage": sys.argv[2], "exit_code": int(sys.argv[3])}, indent=2) + "\n")
PY
  fi
  # WORK is created by mktemp, never supplied by the operator.
  rm -rf -- "$WORK"
  exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for command in python3 curl git ssh scp ssh-keygen qemu-system-x86_64 qemu-img cloud-localds sha256sum; do
  command -v "$command" >/dev/null || { echo "Missing test prerequisite: $command" >&2; exit 2; }
done
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'This isolated test needs access to /dev/kvm.' >&2; exit 2; }
grep -qw avx /proc/cpuinfo || { echo 'The VM host must expose AVX.' >&2; exit 2; }
[[ "$(awk '/MemTotal:/ {print $2}' /proc/meminfo)" -ge 15728640 ]] || { echo 'This test needs at least 16 GB host RAM.' >&2; exit 2; }
[[ "$(df -Pk "$WORK" | awk 'END {print $4}')" -ge 20971520 ]] || { echo 'This test needs 20 GB free workspace storage.' >&2; exit 2; }
[[ ! -e "$REPORT" ]] || { echo 'Choose a new report path; an existing report is never overwritten.' >&2; exit 2; }
python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 22026))
PY

STAGE=image_download
echo 'Ubuntu VM: downloading and checking the official image.'
BASE=https://cloud-images.ubuntu.com/releases/26.04/release
IMAGE=ubuntu-26.04-server-cloudimg-amd64.img
curl --fail --silent --show-error --location --retry 3 --max-time 600 "$BASE/$IMAGE" -o "$WORK/$IMAGE"
curl --fail --silent --show-error --location --retry 3 --max-time 60 "$BASE/SHA256SUMS" -o "$WORK/SHA256SUMS"
python3 - "$WORK" "$IMAGE" <<'PY'
import hashlib, pathlib, sys
work, image = pathlib.Path(sys.argv[1]), sys.argv[2]
entries = [line.split() for line in (work / "SHA256SUMS").read_text().splitlines()]
expected = [parts[0] for parts in entries if len(parts) == 2 and parts[1].lstrip("*") == image]
if len(expected) != 1:
    raise SystemExit("Official image checksum was not found uniquely")
with (work / image).open("rb") as stream:
    actual = hashlib.file_digest(stream, "sha256").hexdigest()
if actual != expected[0]:
    raise SystemExit("Official cloud image checksum mismatch")
(work / "image-sha256").write_text(actual)
PY
qemu-img create -q -f qcow2 -F qcow2 -b "$WORK/$IMAGE" "$WORK/guest.qcow2" 60G
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_vm"
PUBLIC_KEY="$(cat "$WORK/id_vm.pub")"
cat > "$WORK/user-data" <<EOF
#cloud-config
hostname: siem-lab
disable_root: false
ssh_pwauth: false
ssh_authorized_keys:
  - $PUBLIC_KEY
write_files:
  - path: /etc/ssh/sshd_config.d/90-omni-test.conf
    permissions: '0600'
    content: |
      PermitRootLogin prohibit-password
EOF
printf 'instance-id: omni-ubuntu-test\nlocal-hostname: siem-lab\n' > "$WORK/meta-data"
cloud-localds "$WORK/seed.img" "$WORK/user-data" "$WORK/meta-data"
git -C "$ROOT" bundle create "$WORK/source.bundle" HEAD > "$WORK/bundle.log" 2>&1
if [[ "${OMNI_VM_PACKAGE:-0}" == 1 ]]; then
  STAGE=package_build
  if ! python3 "$ROOT/tools/build-release.py" --format deb --output "$WORK/packages" > "$WORK/package-build.log" 2>&1; then
    tail -n 20 "$WORK/package-build.log" >&2
    exit 1
  fi
fi
STAGE=boot
echo 'Ubuntu VM: booting the isolated guest.'
qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 16384 -display none \
  -drive "file=$WORK/guest.qcow2,format=qcow2,if=virtio" \
  -drive "file=$WORK/seed.img,format=raw,if=virtio" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22026-:22 -device virtio-net-pci,netdev=net0 \
  -serial "file:$WORK/serial.log" -monitor none > "$WORK/qemu.log" 2>&1 &
VM_PID=$!
SSH=(-i "$WORK/id_vm" -p 22026 -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$WORK/known_hosts" root@127.0.0.1)
READY=0
for _ in $(seq 1 120); do
  kill -0 "$VM_PID" 2>/dev/null || { echo 'The isolated VM stopped during boot.' >&2; exit 1; }
  if ssh "${SSH[@]}" 'true' > "$WORK/ssh.log" 2>&1; then READY=1; break; fi
  sleep 5
done
[[ "$READY" == 1 ]] || { echo 'The isolated VM did not become reachable.' >&2; exit 1; }
ssh "${SSH[@]}" 'timeout 300 cloud-init status --wait >/dev/null && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git python3' > "$WORK/bootstrap.log" 2>&1
scp -q -i "$WORK/id_vm" -P 22026 -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$WORK/known_hosts" "$WORK/source.bundle" root@127.0.0.1:/root/source.bundle > "$WORK/copy.log" 2>&1
if [[ "${OMNI_VM_PACKAGE:-0}" == 1 ]]; then
  scp -q -i "$WORK/id_vm" -P 22026 -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$WORK/known_hosts" "$WORK"/packages/*.deb root@127.0.0.1:/root/omni-siem.deb > "$WORK/package-copy.log" 2>&1
fi

STAGE=installation
echo 'Ubuntu VM: applying the complete fresh installation.'
INSTALL_CODE=0
ssh "${SSH[@]}" 'bash -s' > "$WORK/install.log" 2>&1 <<'GUEST' || INSTALL_CODE=$?
set -euo pipefail
umask 077
if [[ -f /root/omni-siem.deb ]]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/omni-siem.deb
  omni-siem --root /opt/omni-siem-setup init --apply >/root/package-init.json
  cd /opt/omni-siem-setup
else
  mkdir -p /opt/omni-siem-setup
  cd /opt/omni-siem-setup
  git init -q
  git fetch -q /root/source.bundle HEAD
  git checkout -q -b main FETCH_HEAD
  cp 00-vars.env.example 00-vars.env
fi
installer() {
  if [[ -f /root/omni-siem.deb ]]; then omni-siem --root /opt/omni-siem-setup install "$@";
  else bash install.sh "$@"; fi
}
python3 - <<'PY'
import pathlib, re, secrets, shlex, subprocess
path = pathlib.Path("00-vars.env")
route = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True).split()
updates = dict(SIEM_HOSTNAME="siem", SIEM_DOMAIN="lab.test", SIEM_FQDN="siem.lab.test",
    SIEM_IP="10.0.2.15", SIEM_PREFIX="24", SIEM_GW="10.0.2.2", SIEM_IFACE=route[route.index("dev") + 1],
    APPLY_NETWORK="0", DNS1="10.0.2.3", DNS2="10.0.2.3", NTP1="ntp.ubuntu.com", NTP2="ntp.ubuntu.com",
    NET_ADMIN="10.0.2.0/24", WEB_NET="10.0.2.0/24", NET_BEATS="10.0.2.0/24", VSPHERE_NET="", IP_FAZ="", IP_CENTREON="",
    OS_HEAP="4g", GL_HEAP="2g", MONGO_CACHE_GB="1", JOURNAL_SIZE="1gb", DATA_DISK="", DATA_MOUNT="/data",
    ALLOW_FORMAT_DATA_DISK="0", BACKUP_DIR="/var/backups/omni-siem", RETENTION_DAYS="2", SMTP_RELAY="127.0.0.1",
    SMTP_PORT="25", SMTP_FROM="siem@example.test", ALERT_EMAIL="soc@example.test", GRAYLOG_ADMIN_PASS="Aa1!" + secrets.token_urlsafe(36))
text = path.read_text()
for key, value in updates.items():
    text = re.sub(r"(?m)^" + re.escape(key) + r"=.*$", lambda _: key + "=" + shlex.quote(value), text)
path.write_text(text)
path.chmod(0o600)
PY
installer --generate-secrets >/root/generated-keys.json
installer --plan --experimental-ubuntu-2604 >/root/install-plan.json
python3 - <<'PY'
import json
plan = json.load(open("/root/install-plan.json"))
if plan["blockers"]:
    raise SystemExit("Fresh installation plan has blockers")
PY
if [[ -f /root/omni-siem.deb ]]; then
  timeout 1800 omni-siem --root /opt/omni-siem-setup install --apply --experimental-ubuntu-2604 >/root/install-output.log 2>&1
else
  timeout 1800 bash install.sh --apply --experimental-ubuntu-2604 >/root/install-output.log 2>&1
fi
GUEST

STAGE=verification
echo 'Ubuntu VM: checking installed services and published assets.'
VERIFY_CODE=0
ssh "${SSH[@]}" 'cd /opt/omni-siem-setup && python3 tools/verify-installation.py --output /root/acceptance.json' > "$WORK/verify.log" 2>&1 || VERIFY_CODE=$?
INTEGRATION_CODE=1
if [[ "$INSTALL_CODE" == 0 && "$VERIFY_CODE" == 0 ]]; then
  STAGE=integration_packs
  echo 'Ubuntu VM: checking console sessions, integration events and a complete backup.'
  INTEGRATION_CODE=0
  ssh "${SSH[@]}" 'cd /opt/omni-siem-setup && install -m 600 /dev/null /run/omni-isolated-vm-test && OMNI_ISOLATED_VM_TEST=1 python3 tools/test-integration-vm.py --output /root/integrations-acceptance.json' > "$WORK/integrations.log" 2>&1 || INTEGRATION_CODE=$?
  ssh "${SSH[@]}" 'cat /root/integrations-acceptance.json' > "$WORK/integrations.json" 2> "$WORK/integrations-errors.log" || true
fi
# Optional complete restore drill: synthetic backups made in this guest, simulated loss,
# then the timed drill. Nothing from production is used and nothing leaves the guest
# except the drill's JSON report (no secret: counts, durations, names).
DRILL_ENABLED="${OMNI_VM_RESTORE_DRILL:-0}"
DRILL_CODE=0
if [[ "$DRILL_ENABLED" == 1 ]]; then
  DRILL_CODE=1
  if [[ "$INTEGRATION_CODE" == 0 ]]; then
    STAGE=restore_drill
    echo 'Ubuntu VM: timed complete restore drill from synthetic backups.'
    DRILL_CODE=0
    ssh "${SSH[@]}" 'cd /opt/omni-siem-setup && export OMNI_ISOLATED_VM_TEST=1 && python3 tools/omni-restore-drill.py jeu-factice --sortie /root/drill-src && python3 tools/omni-restore-drill.py sinistre-factice --jeu /root/drill-src/jeu.json && OMNI_RESTORE_DRILL_ISOLATED=1 python3 tools/omni-restore-drill.py executer --jeu /root/drill-src/jeu.json --rapport /root/drill-report' > "$WORK/drill.log" 2>&1 || DRILL_CODE=$?
    ssh "${SSH[@]}" 'cat /root/drill-report/rapport-restauration.json' > "$WORK/drill.json" 2> "$WORK/drill-errors.log" || true
  fi
fi
if [[ "$INSTALL_CODE" != 0 || "$VERIFY_CODE" != 0 || "$INTEGRATION_CODE" != 0 || "$DRILL_CODE" != 0 ]]; then
  # Only the disposable test guest's redacted diagnostics may leave the VM.
  ssh "${SSH[@]}" 'cd /opt/omni-siem-setup && python3 -' > "$WORK/diagnose.log" 2>&1 <<'DIAG' || true
import base64, importlib.util, json
from pathlib import Path
from manager.operations import redact
spec = importlib.util.spec_from_file_location("installer", "tools/install-platform.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
config = installer.load_config(Path("00-vars.env"))
private = [value for key, value in config.items() if value and any(word in key for word in ("PASS", "SECRET", "TOKEN", "KEY", "CRED", "WEBHOOK"))]
private.append(base64.b64encode(("admin:" + config["GRAYLOG_ADMIN_PASS"]).encode()).decode())
for name in ("/root/.graylog_password_secret", "/etc/mongod.keyfile"):
    path = Path(name)
    if path.exists():
        private.extend(line for line in path.read_text().splitlines() if len(line) > 16)
report_path = Path("/root/acceptance.json")
report = json.loads(report_path.read_text())
for name, key, count in (("/root/install-output.log", "failure_tail_redacted", 160),
                         ("/var/log/graylog-server/server.log", "graylog_tail_redacted", 60),
                         ("/var/log/siem-backup.log", "backup_tail_redacted", 40)):
    log = Path(name)
    if log.exists():
        report[key] = [redact(line, private)[:1000] for line in log.read_text(errors="replace").splitlines()[-count:]]
plan = Path("/root/install-plan.json")
if plan.exists():
    report["plan_blockers"] = json.loads(plan.read_text()).get("blockers", [])
report_path.write_text(json.dumps(report, indent=2) + "\n")
DIAG
fi
ssh "${SSH[@]}" 'cat /root/acceptance.json' > "$WORK/report.json" 2> "$WORK/report-errors.log" || true
if python3 - "$WORK/report.json" "$INSTALL_CODE" "$WORK/image-sha256" "$WORK/integrations.json" "$VERIFY_CODE" "$INTEGRATION_CODE" "${DRILL_ENABLED:-0}" "${DRILL_CODE:-0}" "$WORK/drill.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
assert isinstance(data.get("passed"), bool)
data["install_exit_code"] = int(sys.argv[2])
data["verify_exit_code"] = int(sys.argv[5])
data["integration_exit_code"] = int(sys.argv[6])
data["cloud_image_sha256"] = pathlib.Path(sys.argv[3]).read_text()
integrations = pathlib.Path(sys.argv[4])
data["integrations"] = json.loads(integrations.read_text()) if integrations.is_file() else {"passed": False, "skipped": True}
data["passed"] = data["passed"] and all(data[key] == 0 for key in ("install_exit_code", "verify_exit_code", "integration_exit_code")) and data["integrations"].get("passed") is True
if sys.argv[7] == "1":
    drill = pathlib.Path(sys.argv[9])
    try:
        data["restore_drill"] = json.loads(drill.read_text()) if drill.is_file() and drill.stat().st_size else {"reussi": False, "absent": True}
    except ValueError:
        data["restore_drill"] = {"reussi": False, "invalide": True}
    data["restore_drill_exit_code"] = int(sys.argv[8])
    data["passed"] = data["passed"] and data["restore_drill_exit_code"] == 0 and data["restore_drill"].get("reussi") is True
path.write_text(json.dumps(data, indent=2) + "\n")
PY
then
  install -m 600 "$WORK/report.json" "$REPORT"
else
  echo 'Ubuntu VM acceptance report is missing or invalid.' >&2
  exit 1
fi
[[ "$INSTALL_CODE" == 0 && "$VERIFY_CODE" == 0 && "$INTEGRATION_CODE" == 0 && "${DRILL_CODE:-0}" == 0 ]] || { echo "Ubuntu VM acceptance failed; inspect the sanitized JSON report." >&2; exit 1; }
python3 - "$REPORT" <<'PY'
import json, sys
if json.load(open(sys.argv[1])).get("passed") is not True:
    raise SystemExit("The aggregated Ubuntu VM report did not pass")
PY
python3 - "$REPORT" "${OMNI_VM_PACKAGE:-0}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_text())
report["distribution_package"] = sys.argv[2] == "1"
path.write_text(json.dumps(report, indent=2) + "\n")
PY
echo "Ubuntu 26.04 fresh installation passed; report: $REPORT"
