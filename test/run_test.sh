#!/usr/bin/env bash
# Local integration test for portstealer.
# Run via: make test  (which calls this script)
set -e
cd "$(dirname "$0")/.."

REMOTE_PORT=29990
LOCAL_PORT=19999
SOAP_PORT=19998
CLIENT_PORT=29991
PASS=0
FAIL=0

ok()   { echo "[PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }

cleanup() {
    pkill -f 'test/server2'            2>/dev/null || true
    pkill -f "client.py.*$CLIENT_PORT" 2>/dev/null || true
    fuser -k ${REMOTE_PORT}/tcp        2>/dev/null || true
}
trap cleanup EXIT

cleanup
sleep 0.3

# ── 1. remote echo server (simulates FortiGate) ───────────────────────────────
python3 - <<'EOF' > /tmp/remote.log 2>&1 &
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 29990)); s.listen(8)
print('[remote] listening on :29990', flush=True)
def handle(c):
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(d)
    except: pass
    finally: c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
EOF
sleep 0.3

# ── 2. server2 ────────────────────────────────────────────────────────────────
LD_LIBRARY_PATH=test test/server2 > /tmp/srv2.log 2>&1 &
sleep 0.5
echo "[setup] server2 pid: $(pgrep -f 'test/server2')"

# ── 3. inject with scope_port=0 (intercept all ports) ────────────────────────
# portstealer also sends a kickstart to LOCAL_PORT so the hook fires from now on.
echo "[setup] injecting into port $LOCAL_PORT → 127.0.0.1:$REMOTE_PORT (scope=all)"
./portstealer $LOCAL_PORT 127.0.0.1 $REMOTE_PORT 0 > /tmp/ps_test.log 2>&1
cat /tmp/ps_test.log

# ── 4. Kickstart the soap thread (port 19998 / libwrap.so) ───────────────────
# The soap thread was also blocked in accept() before injection; wake it up.
python3 -c "
import socket
s = socket.socket()
s.settimeout(0.5)
try: s.connect(('127.0.0.1', $SOAP_PORT)); s.close()
except: pass
" 2>/dev/null
sleep 0.3

# ── 5. client proxy ───────────────────────────────────────────────────────────
python3 client.py $CLIENT_PORT 127.0.0.1 $LOCAL_PORT > /tmp/client.log 2>&1 &
sleep 0.3

# ── test 1: magic → direct port → tunnel (echo back) ─────────────────────────
echo ""
echo "--- test 1: magic via direct port ($LOCAL_PORT) ---"
result=$(python3 - <<EOF
import socket
MAGIC = b'\xbc\xbc\x05\x00\xde\xad\xbe\xef'
s = socket.socket()
s.connect(('127.0.0.1', $CLIENT_PORT))
s.sendall(MAGIC + b'hello tunnel')
s.settimeout(3)
try:
    d = s.recv(64)
    print('got:' + repr(d))
except Exception as e:
    print('err:' + str(e))
s.close()
EOF
)
echo "$result"
# Pass only if we received actual non-empty data (echo)
if [[ "$result" =~ ^got:b\'.+\' ]]; then
    ok "direct port tunneled"
else
    fail "direct port not tunneled (got: $result)"
fi

# ── test 2: non-magic → server2 handles it, no echo ──────────────────────────
echo ""
echo "--- test 2: non-magic to direct port ($LOCAL_PORT) ---"
result=$(python3 - <<EOF
import socket
s = socket.socket()
s.connect(('127.0.0.1', $LOCAL_PORT))
s.settimeout(2)
try:
    d = s.recv(64)
    print('got:' + repr(d))
except socket.timeout:
    print('timeout')
except Exception as e:
    print('closed:' + str(e))
s.close()
EOF
)
echo "$result"
# Pass if no actual echo data (b'', timeout, or closed — all mean not tunneled)
if [[ "$result" == "got:b''" ]] || [[ "$result" == timeout ]] || [[ "$result" == closed:* ]]; then
    ok "non-magic not tunneled"
else
    fail "non-magic was tunneled (wrong): $result"
fi

# ── test 3: magic → soap port (libwrap.so GOT) → tunnel ──────────────────────
echo ""
echo "--- test 3: magic via soap port ($SOAP_PORT / libwrap.so) ---"
result=$(python3 - <<EOF
import socket
MAGIC = b'\xbc\xbc\x05\x00\xde\xad\xbe\xef'
s = socket.socket()
s.connect(('127.0.0.1', $SOAP_PORT))
s.sendall(MAGIC + b'soap tunnel')
s.settimeout(3)
try:
    d = s.recv(64)
    print('got:' + repr(d))
except Exception as e:
    print('err:' + str(e))
s.close()
EOF
)
echo "$result"
if [[ "$result" =~ ^got:b\'.+\' ]]; then
    ok "soap port tunneled"
else
    fail "soap port not tunneled (got: $result)"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ]
