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
STAGE=boot
qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 16384 -display none \
  -drive "file=$WORK/guest.qcow2,format=qcow2,if=virtio" \
  -drive "file=$WORK/seed.img,format=raw,if=virtio" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22026-:22 -device virtio-net-pci,netdev=net0 \
  -serial "file:$WORK/serial.log" -monitor none > "$WORK/qemu.log" 2>&1 &
VM_PID=$!
SSH=(-i "$WORK/id_vm" -p 22026 -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$WORK/known_hosts" root@127.0.0.1)
READY=0
for attempt in $(seq 1 120); do
  kill -0 "$VM_PID" 2>/dev/null || { echo 'The isolated VM stopped during boot.' >&2; exit 1; }
  if ssh "${SSH[@]}" 'true' > "$WORK/ssh.log" 2>&1; then READY=1; break; fi
  sleep 5
done
[[ "$READY" == 1 ]] || { echo 'The isolated VM did not become reachable.' >&2; exit 1; }
ssh "${SSH[@]}" 'timeout 300 cloud-init status --wait >/dev/null && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git python3' > "$WORK/bootstrap.log" 2>&1
scp -q -i "$WORK/id_vm" -P 22026 -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$WORK/known_hosts" "$WORK/source.bundle" root@127.0.0.1:/root/source.bundle > "$WORK/copy.log" 2>&1

STAGE=installation
INSTALL_CODE=0
ssh "${SSH[@]}" 'bash -s' > "$WORK/install.log" 2>&1 <<'GUEST' || INSTALL_CODE=$?
set -euo pipefail
umask 077
mkdir -p /opt/omni-siem-setup
cd /opt/omni-siem-setup
git init -q
git fetch -q /root/source.bundle HEAD
git checkout -q -b main FETCH_HEAD
cp 00-vars.env.example 00-vars.env
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
bash install.sh --generate-secrets >/root/generated-keys.json
bash install.sh --plan --experimental-ubuntu-2604 >/root/install-plan.json
python3 - <<'PY'
import json
plan = json.load(open("/root/install-plan.json"))
if plan["blockers"]:
    raise SystemExit("Fresh installation plan has blockers")
PY
timeout 1800 bash install.sh --apply --experimental-ubuntu-2604 >/root/install-output.log 2>&1
GUEST

STAGE=verification
VERIFY_CODE=0
ssh "${SSH[@]}" 'cd /opt/omni-siem-setup && python3 tools/verify-installation.py --output /root/acceptance.json' > "$WORK/verify.log" 2>&1 || VERIFY_CODE=$?
ssh "${SSH[@]}" 'cat /root/acceptance.json' > "$WORK/report.json" 2> "$WORK/report-errors.log" || true
if python3 - "$WORK/report.json" "$INSTALL_CODE" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
assert isinstance(data.get("passed"), bool)
data["install_exit_code"] = int(sys.argv[2])
data["passed"] = data["passed"] and data["install_exit_code"] == 0
path.write_text(json.dumps(data, indent=2) + "\n")
PY
then
  install -m 600 "$WORK/report.json" "$REPORT"
fi
[[ "$INSTALL_CODE" == 0 && "$VERIFY_CODE" == 0 ]] || { echo "Ubuntu VM acceptance failed; inspect the sanitized JSON report." >&2; exit 1; }
echo "Ubuntu 26.04 fresh installation passed; report: $REPORT"
