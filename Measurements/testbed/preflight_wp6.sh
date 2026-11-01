#!/usr/bin/env bash
# Preflight for the WP6 measurements: checks, one by one, everything run_all_wp6.sh needs, and prints the command that fixes each problem.
#   sudo --preserve-env=SSH_AUTH_SOCK bash preflight_wp6.sh        # about 20 s; exit code 1 if any FAIL
# FAIL = a scenario cannot run; WARN = a scenario will be skipped or less useful; OK = fine.
cd "$(dirname "$0")"
HERE=$PWD
fails=0; warns=0
ok()   { echo "  OK    $*"; }
warn() { echo "  WARN  $*"; warns=$((warns + 1)); }
fail() { echo "  FAIL  $*"; fails=$((fails + 1)); }
sect() { echo; echo "== $*"; }
U=${SUDO_USER:-$(id -un)}
as_user() { if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then sudo -u "$U" -H env ${SSH_AUTH_SOCK:+SSH_AUTH_SOCK="$SSH_AUTH_SOCK"} "$@"; else "$@"; fi; }

sect "privileges"
[ "$(id -u)" = 0 ] && ok "running as root (through sudo, user $U)" || fail "not root: run  sudo --preserve-env=SSH_AUTH_SOCK bash preflight_wp6.sh"

sect "programs"
for b in ip tc ethtool taskset lscpu gcc python3 git; do command -v $b >/dev/null && ok "$b" || fail "$b missing: sudo apt install iproute2 ethtool util-linux gcc python3 git"; done
command -v tcpdump >/dev/null && ok "tcpdump (needed by the trace scenario: packet captures)" || fail "tcpdump missing: sudo apt install tcpdump"
command -v perf >/dev/null && ok "perf (needed only for the CPU profile of the capacity scenario)" || warn "perf missing: sudo apt install linux-tools-\$(uname -r) linux-tools-generic; without it the profile is skipped"
python3 -c "import matplotlib" 2>/dev/null && ok "python3 matplotlib" || warn "matplotlib missing (only for the short-paper figures): pip install matplotlib"

sect "kernel tracing (the trace scenario enables the tracepoint tcp:tcp_probe)"
TR=/sys/kernel/tracing
if [ ! -d $TR/events ]; then
  if [ -d /sys/kernel/debug/tracing/events ]; then warn "tracefs only under /sys/kernel/debug/tracing; fix: sudo mount -t tracefs nodev /sys/kernel/tracing"
  else fail "tracefs not mounted; fix: sudo mount -t tracefs nodev /sys/kernel/tracing"; fi
else
  ok "tracefs mounted at $TR"
  if [ -d $TR/events/tcp/tcp_probe ]; then
    ok "tracepoint tcp:tcp_probe exists"
    if [ "$(id -u)" = 0 ]; then
      if echo 1 > $TR/events/tcp/tcp_probe/enable 2>/dev/null && echo 0 > $TR/events/tcp/tcp_probe/enable 2>/dev/null && [ -r $TR/trace_pipe ]; then ok "tracepoint can be enabled and trace_pipe read"
      else fail "cannot write $TR/events/tcp/tcp_probe/enable (secure boot / lockdown?): check  cat /sys/kernel/security/lockdown"; fi
    fi
  else fail "no tracepoint tcp:tcp_probe in this kernel (CONFIG_TCP_PROBE?); the trace scenario cannot run"; fi
fi
[ -r /sys/kernel/security/lockdown ] && echo "        lockdown: $(cat /sys/kernel/security/lockdown)"

sect "perf permission"
if command -v perf >/dev/null; then
  par=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)
  [ "$(id -u)" = 0 ] && ok "root can profile (perf_event_paranoid=$par)" || warn "not root; perf_event_paranoid=$par (<=1 needed for non-root): sudo sysctl kernel.perf_event_paranoid=1"
  [ "$(id -u)" = 0 ] && { perf stat -e task-clock true >/dev/null 2>&1 && ok "perf stat works" || warn "perf stat failed: the kernel and perf package versions must match (sudo apt install linux-tools-\$(uname -r))"; }
fi

sect "namespaces, virtual links, netem, packet capture"
if [ "$(id -u)" = 0 ]; then
  ip netns del wp6pre 2>/dev/null; ip link del wp6a 2>/dev/null
  if ip netns add wp6pre 2>/dev/null; then ok "network namespaces"
    if ip link add wp6a type veth peer name wp6b 2>/dev/null; then ok "veth pairs"
      ip link set wp6b netns wp6pre 2>/dev/null; ip link set wp6a up
      if tc qdisc add dev wp6a root netem delay 5ms rate 100mbit 2>/dev/null; then ok "tc netem (delay, rate)"; tc qdisc add dev wp6a parent 1: handle 2: netem loss 1% 2>/dev/null; else fail "tc netem missing: sudo apt install linux-modules-extra-\$(uname -r); sudo modprobe sch_netem"; fi
      ethtool -K wp6a tso off gso off gro off >/dev/null 2>&1 && ok "ethtool can switch offloads off" || warn "ethtool -K failed on veth (offload setting); the testbed continues but check Paper 1 notes"
      command -v tcpdump >/dev/null && { timeout 3 tcpdump -i wp6a -c 1 -w /dev/null >/dev/null 2>&1; [ $? -ne 1 ] && ok "tcpdump can open an interface" || fail "tcpdump cannot capture (permissions or AppArmor): check  sudo tcpdump -i lo -c 1"; }
      ip link del wp6a 2>/dev/null
    else fail "cannot create veth pairs (module veth): sudo modprobe veth"; fi
    ip netns del wp6pre 2>/dev/null
  else fail "cannot create network namespaces: run as root"; fi
else warn "namespace test skipped (not root)"; fi

sect "tools built and certificates"
for b in tls_probe tls_serve tls_load tls_load_open tcp_flight; do
  [ -x $b ] && ok "$b" || { [ $b = tls_load_open ] || [ $b = tcp_flight ] && warn "$b not built (run_all_wp6.sh builds it)" || fail "$b not built: ./setup_host.sh"; }
done
P=$(as_user bash -c 'echo ${PQC_OPENSSL:-$HOME/opt/openssl-3.5}')
if [ -x "$P/bin/openssl" ]; then v=$(LD_LIBRARY_PATH=$P/lib "$P/bin/openssl" version 2>/dev/null); ok "OpenSSL: $v ($P)"; case "$v" in *" 3.5."*|*" 3.6."*|*" 4."*) ;; *) warn "OpenSSL should be 3.5 or newer (ML-DSA, ML-KEM)";; esac
else fail "OpenSSL 3.5 not found at $P: ./setup_host.sh (or export PQC_OPENSSL=/path)"; fi
miss=0
for alg in ECDSA-P256 ML-DSA-44 ML-DSA-65 ML-DSA-87; do for d in d2 d3; do
  for f in server.key client.key root.pem inter_chain.pem; do [ -e ../certs/$alg/$d/$f ] || { miss=$((miss + 1)); echo "        missing ../certs/$alg/$d/$f"; }; done
done; done
[ $miss = 0 ] && ok "certificates and private keys for ECDSA-P256, ML-DSA-44/65/87, depth 2 and 3" || fail "certificate files missing (keys are not in the repository): (cd .. && ./certs.sh)  [it regenerates the .pem files of the repository]"

sect "machine"
echo "        kernel: $(uname -r)    cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
cores=$(lscpu -p=CORE,SOCKET 2>/dev/null | grep -v '^#' | sort -u | wc -l)
[ "$cores" -ge 2 ] && ok "$cores physical cores (server and client on separate cores)" || fail "only $cores physical core: the testbed needs two"
[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ] && ok "cpufreq governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor) (host_tune.sh will set performance)" || warn "no cpufreq interface: host_tune.sh cannot fix the frequency (timings will be noisier)"
l=$(cut -d' ' -f1 /proc/loadavg); awk -v l="$l" 'BEGIN{exit !(l < 0.7)}' && ok "machine idle (load average $l)" || warn "load average $l: close other programs before starting"
free=$(df -Pm "$HERE" | awk 'NR==2{print int($4/1024)}'); [ "${free:-0}" -ge 5 ] && ok "free disk space ${free} GB" || warn "only ${free} GB free (traces and raw results need about 2 GB)"
command -v systemd-inhibit >/dev/null && ok "systemd-inhibit available (run_all_wp6.sh keeps the machine from sleeping)" || warn "no systemd-inhibit: disable suspend yourself (screen lock is fine, sleep is not)"
echo "        on a laptop: keep the charger plugged in and the lid open (or set the lid action to 'ignore')"

sect "session and network"
echo "        systemd target now: $(systemctl get-default 2>/dev/null) (default); active: $(systemctl list-units --type=target --state=active --no-legend 2>/dev/null | grep -oE 'graphical.target|multi-user.target' | tr '\n' ' ')"
if systemctl is-active --quiet NetworkManager 2>/dev/null; then ok "NetworkManager active (network survives the text mode)"; elif systemctl is-active --quiet systemd-networkd 2>/dev/null; then ok "systemd-networkd active"; else warn "no network manager active: check the connection (needed for the automatic pushes)"; fi
getent hosts github.com >/dev/null 2>&1 && ok "DNS resolves github.com" || warn "github.com does not resolve: the pushes will fail"
sect "git and GitHub (for the automatic commits)"
R=$(git rev-parse --show-toplevel 2>/dev/null) && ok "repository $R" || fail "not inside a git repository"
if [ -n "$R" ]; then
  [ -n "$(as_user git -C "$R" config user.email)" ] && ok "git user: $(as_user git -C "$R" config user.name) <$(as_user git -C "$R" config user.email)>" || fail "git user not set: git config --global user.name 'Your Name'; git config --global user.email you@example.com"
  rem=$(as_user git -C "$R" remote get-url origin 2>/dev/null); [ -n "$rem" ] && ok "origin: $rem" || fail "no git remote 'origin'"
  case "$rem" in git@*|ssh://*)
    sshcmd=$(as_user git -C "$R" config core.sshCommand)
    if [ -n "$sshcmd" ]; then
      kf=$(echo "$sshcmd" | grep -oE -- '-i +[^ ]+' | head -1 | sed 's/^-i *//; s#^~#'"$(as_user bash -c 'echo $HOME')"'#')
      if [ -n "$kf" ] && [ -r "$kf" ]; then ok "deploy key through core.sshCommand ($kf): no ssh agent needed"
        [ "$(stat -c %a "$kf" 2>/dev/null)" = 600 ] && ok "key file permissions 600" || warn "key file permissions should be 600: chmod 600 $kf"
      else warn "core.sshCommand is set but the key file was not found or not readable by $U: $sshcmd"; fi
    elif [ -n "${SSH_AUTH_SOCK:-}" ]; then
      ok "ssh agent visible (SSH_AUTH_SOCK)"
      k=$(as_user ssh-add -l 2>&1); case "$k" in *"no identities"*|*"Could not open"*|*"Error"*) warn "the ssh agent holds no key: run  ssh-add  (as your user, before sudo)";; *) ok "ssh agent holds $(echo "$k" | grep -c .) key(s)";; esac
    else warn "no ssh agent in this sudo session: in a text console run  eval \$(ssh-agent) && ssh-add  and use  sudo --preserve-env=SSH_AUTH_SOCK ...  (or a key without passphrase)"; fi;; esac
  err=$(as_user timeout 40 env GIT_TERMINAL_PROMPT=0 git -C "$R" ls-remote -q origin HEAD 2>&1 >/dev/null); rc=$?
  if [ $rc = 0 ]; then ok "GitHub reachable and authenticated (ls-remote works as $U)"
  else
    fail "cannot reach origin as $U (rc=$rc)"
    echo "$err" | tail -4 | sed 's/^/        git said: /'
    case "$err" in
      *"could not read Username"*|*"Authentication failed"*|*"terminal prompts disabled"*) echo "        cause: the remote is HTTPS. Fix: git -C $R remote set-url origin git@github.com:tronghieudinh/PQC-bank.git";;
      *"Host key verification failed"*) echo "        cause: github.com is not in ~$U/.ssh/known_hosts. Fix, AS $U (not with sudo): ssh-keyscan -t ed25519 github.com >> ~/.ssh/known_hosts";;
      *"Permission denied (publickey)"*) echo "        cause: GitHub does not accept the key. Check: the public key is in the repository's Settings > Deploy keys (write access ticked); git -C $R config core.sshCommand points to the right file; test: sudo -u $U -H ssh -i ~$U/.ssh/pqcbank_deploy -o IdentitiesOnly=yes -o BatchMode=yes -T git@github.com";;
      *"UNPROTECTED PRIVATE KEY"*|*"bad permissions"*|*"Load key"*) echo "        cause: the key file is not readable/owned by $U or its mode is wrong. Fix: sudo chown $U ~$U/.ssh/pqcbank_deploy; chmod 600 ~$U/.ssh/pqcbank_deploy";;
      *"Could not resolve hostname"*|*"Temporary failure"*|*"Network is unreachable"*|*"timed out"*) echo "        cause: no network or DNS from this session. Check: ping -c 2 github.com; systemctl status NetworkManager";;
      *"Repository not found"*|*"not found"*) echo "        cause: wrong repository name or the key is not a deploy key of THIS repository";;
      *) echo "        run by hand to see more: sudo -u $U -H env GIT_SSH_COMMAND='ssh -v' git -C $R ls-remote origin HEAD";;
    esac
  fi
  b=$(as_user git -C "$R" rev-parse --abbrev-ref HEAD); ok "branch: $b"
fi

echo; echo "== result: $fails FAIL, $warns WARN"
[ $fails = 0 ] && echo "Ready: sudo --preserve-env=SSH_AUTH_SOCK bash run_all_wp6.sh   (inside tmux or screen, so that closing the terminal does not stop it)" || echo "Fix the FAIL lines above, then run this check again."
[ $fails = 0 ]
