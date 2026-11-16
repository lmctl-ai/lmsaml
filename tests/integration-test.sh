#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SERVER_BIN="$ROOT_DIR/lmsaml"
if [ ! -x "$SERVER_BIN" ]; then
    echo "Error: lmsaml binary not found at $SERVER_BIN"
    exit 1
fi

SAML_PORT=28480
REST_PORT=28481
ADMIN_USER="admin"
ADMIN_PW="admin-secret-pw"
TEST_DIR=$(mktemp -d /tmp/lmsaml_test_XXXXXX)
LOG_FILE="$TEST_DIR/server.log"

cleanup() {
    local exit_code=$?
    echo "=== Cleaning up ==="
    if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Stopping server process $SERVER_PID..."
        kill "$SERVER_PID" || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ $exit_code -ne 0 ] && [ -f "$LOG_FILE" ]; then
        echo "=== Server Log on Failure ==="
        tail -n 60 "$LOG_FILE" || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "=== Starting lmsaml on SAML port $SAML_PORT, REST port $REST_PORT ==="
"$SERVER_BIN" \
    --port "$SAML_PORT" \
    --rest-port "$REST_PORT" \
    --admin-user "$ADMIN_USER" \
    --admin-password "$ADMIN_PW" > "$LOG_FILE" 2>&1 &
SERVER_PID=$!

echo "Waiting for server to become ready..."
MAX_RETRIES=50
READY=0
for i in $(seq 1 $MAX_RETRIES); do
    if curl -s "http://127.0.0.1:$SAML_PORT/ping" | grep -q "PONG"; then
        READY=1
        break
    fi
    sleep 0.1
done

if [ $READY -eq 0 ]; then
    echo "Error: lmsaml failed to start within timeout."
    exit 1
fi
echo "Server is ready!"

echo "=========================================================="
echo "TEST SECTION 1: SAML 2.0 Protocol Endpoints (IdP & SP)"
echo "=========================================================="

echo -n "Test 1.1: SAML 2.0 IdP Metadata (/idp/metadata)... "
IDP_META=$(curl -s "http://127.0.0.1:$SAML_PORT/idp/metadata")
echo "$IDP_META" | grep -q "EntityDescriptor" || { echo "FAIL EntityDescriptor"; exit 1; }
echo "$IDP_META" | grep -q "IDPSSODescriptor" || { echo "FAIL IDPSSODescriptor"; exit 1; }
echo "$IDP_META" | grep -q "SingleSignOnService" || { echo "FAIL SingleSignOnService"; exit 1; }
echo "$IDP_META" | grep -q "X509Certificate" || { echo "FAIL X509Certificate"; exit 1; }
echo "OK"

echo -n "Test 1.2: SAML 2.0 SP Metadata (/sp/metadata)... "
SP_META=$(curl -s "http://127.0.0.1:$SAML_PORT/sp/metadata")
echo "$SP_META" | grep -q "EntityDescriptor" || { echo "FAIL EntityDescriptor"; exit 1; }
echo "$SP_META" | grep -q "SPSSODescriptor" || { echo "FAIL SPSSODescriptor"; exit 1; }
echo "$SP_META" | grep -q "AssertionConsumerService" || { echo "FAIL AssertionConsumerService"; exit 1; }
echo "OK"

echo -n "Test 1.3: SP-Initiated SAML AuthnRequest Redirect (/sp/hello)... "
REDIRECT_HEADERS=$(curl -s -D - -o /dev/null "http://127.0.0.1:$SAML_PORT/sp/hello")
echo "$REDIRECT_HEADERS" | grep -q "302 Found" || { echo "FAIL 302 (got $REDIRECT_HEADERS)"; exit 1; }
echo "$REDIRECT_HEADERS" | grep -qi "Location: .*/idp/sso?SAMLRequest=" || { echo "FAIL Location SAMLRequest (got $REDIRECT_HEADERS)"; exit 1; }
echo "OK"

echo "=========================================================="
echo "TEST SECTION 2: REST API & User / Service Management"
echo "=========================================================="

echo -n "Test 2.1: REST /ping on both ports... "
PING1=$(curl -s "http://127.0.0.1:$SAML_PORT/ping")
PING2=$(curl -s "http://127.0.0.1:$REST_PORT/ping")
echo "$PING1" | grep -q '"result":"PONG"' || { echo "FAIL port1 ($PING1)"; exit 1; }
echo "$PING2" | grep -q '"result":"PONG"' || { echo "FAIL port2 ($PING2)"; exit 1; }
echo "OK"

echo -n "Test 2.2: REST PUT /users/alice & GET /users/alice... "
ADD_ALICE=$(curl -s -X PUT "http://127.0.0.1:$REST_PORT/users/alice" \
    -H "Content-Type: application/json" \
    -d '{"password":"alice-password-123","email":"alice@example.com","common_name":"Alice Wonderland","surname":"Wonderland","given_name":"Alice","groups":["eng","security"]}')
echo "$ADD_ALICE" | grep -q '"ok":true' || { echo "FAIL add ($ADD_ALICE)"; exit 1; }
GET_ALICE=$(curl -s "http://127.0.0.1:$REST_PORT/users/alice")
echo "$GET_ALICE" | grep -q '"email":"alice@example.com"' || { echo "FAIL get ($GET_ALICE)"; exit 1; }
echo "$GET_ALICE" | grep -q '"Alice Wonderland"' || { echo "FAIL cn ($GET_ALICE)"; exit 1; }
echo "OK"

echo -n "Test 2.3: REST GET /users & GET /services... "
USERS_LIST=$(curl -s "http://127.0.0.1:$REST_PORT/users")
echo "$USERS_LIST" | grep -q '"alice"' || { echo "FAIL users ($USERS_LIST)"; exit 1; }
SERVICES_LIST=$(curl -s "http://127.0.0.1:$REST_PORT/services")
echo "$SERVICES_LIST" | grep -q '"sp-default"' || { echo "FAIL services ($SERVICES_LIST)"; exit 1; }
echo "OK"

echo "=========================================================="
echo "TEST SECTION 3: Authn & Cryptographic SAML 2.0 Assertions"
echo "=========================================================="

echo -n "Test 3.1: REST POST /authn with valid & invalid credentials... "
AUTH_OK=$(curl -s -X POST "http://127.0.0.1:$REST_PORT/authn" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"alice-password-123"}')
echo "$AUTH_OK" | grep -q '"authenticated":true' || { echo "FAIL valid authn ($AUTH_OK)"; exit 1; }
AUTH_BAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$REST_PORT/authn" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"wrong-password"}')
[ "$AUTH_BAD_CODE" = "401" ] || { echo "FAIL invalid authn code ($AUTH_BAD_CODE)"; exit 1; }
echo "OK"

echo -n "Test 3.2: Issue & cryptographically verify signed SAML 2.0 Assertion... "
ISSUED_JSON=$(curl -s -X POST "http://127.0.0.1:$REST_PORT/assertion" \
    -H "Content-Type: application/json" \
    -d '{"user":"alice"}')
echo "$ISSUED_JSON" | grep -q '"ok":true' || { echo "FAIL issue ($ISSUED_JSON)"; exit 1; }
B64_RESP=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["saml_response_b64"])' <<< "$ISSUED_JSON")
VERIFY_JSON=$(curl -s -X POST "http://127.0.0.1:$REST_PORT/verify" \
    -H "Content-Type: application/json" \
    -d "{\"saml_response_b64\":\"$B64_RESP\"}")
echo "$VERIFY_JSON" | grep -q '"valid":true' || { echo "FAIL verify ($VERIFY_JSON)"; exit 1; }
echo "$VERIFY_JSON" | grep -q '"subject":"alice@example.com"' || { echo "FAIL subject ($VERIFY_JSON)"; exit 1; }
echo "OK"

echo -n "Test 3.3: Tampered SAML 2.0 Assertion is rejected by XML signature check... "
TAMPERED_XML=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["xml"].replace("alice@example.com","mallory@example.com"))' <<< "$ISSUED_JSON")
TAMPERED_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$REST_PORT/verify" \
    -H "Content-Type: application/xml" \
    --data-binary "$TAMPERED_XML")
[ "$TAMPERED_CODE" = "400" ] || { echo "FAIL tampered code ($TAMPERED_CODE)"; exit 1; }
echo "OK"

echo "=========================================================="
echo "TEST SECTION 4: lmconn SAML Connector Client Tests"
echo "=========================================================="

LMCONN_BIN=""
if [ -f "$ROOT_DIR/../lmconn/bin/lmconn.js" ]; then
    LMCONN_BIN="node $ROOT_DIR/../lmconn/bin/lmconn.js"
elif command -v lmconn >/dev/null 2>&1; then
    LMCONN_BIN="lmconn"
fi

if [ -n "$LMCONN_BIN" ]; then
    echo -n "Test 4.1: lmconn saml ping & metadata... "
    $LMCONN_BIN saml ping --port "$SAML_PORT" | grep -q '"result":"PONG"' || { echo "FAIL ping"; exit 1; }
    $LMCONN_BIN saml metadata --port "$SAML_PORT" | grep -q 'IDPSSODescriptor' || { echo "FAIL metadata"; exit 1; }
    echo "OK"

    echo -n "Test 4.2: lmconn saml user-add, user-get, authn, assertion, verify, user-del... "
    $LMCONN_BIN saml user-add --port "$SAML_PORT" --user bob --email "bob@example.com" --password "bob-pw" | grep -q '"result":"OK"' || { echo "FAIL user-add"; exit 1; }
    $LMCONN_BIN saml user-get --port "$SAML_PORT" --user bob | grep -q '"bob@example.com"' || { echo "FAIL user-get"; exit 1; }
    $LMCONN_BIN saml authn --port "$SAML_PORT" --user bob --password "bob-pw" | grep -q '"authenticated":true' || { echo "FAIL authn"; exit 1; }
    BOB_ASSERT=$($LMCONN_BIN saml assertion --port "$SAML_PORT" --user bob)
    BOB_B64=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["result"]["saml_response_b64"])' <<< "$BOB_ASSERT")
    $LMCONN_BIN saml verify --port "$SAML_PORT" --response "$BOB_B64" | grep -q '"valid":true' || { echo "FAIL verify"; exit 1; }
    $LMCONN_BIN saml user-del --port "$SAML_PORT" --user bob | grep -q '"deleted":1' || { echo "FAIL user-del"; exit 1; }
    echo "OK"
else
    echo "SKIP: lmconn not found"
fi

echo "=========================================================="
echo "TEST SECTION 5: lmcurl SAML Client Integration Tests"
echo "=========================================================="

LMCURL_BIN=""
if [ -x "$ROOT_DIR/../lmcurl/build/lmcurl" ]; then
    LMCURL_BIN="$ROOT_DIR/../lmcurl/build/lmcurl"
elif command -v lmcurl >/dev/null 2>&1; then
    LMCURL_BIN="$(command -v lmcurl)"
fi

if [ -n "$LMCURL_BIN" ] && command -v lmscript >/dev/null 2>&1; then
    echo -n "Test 5.1: lmcurl SAML IdP metadata, user provisioning & assertion flow... "
    LMS_CURL="$TEST_DIR/test_lmcurl.lms"
    cat << EOF > "$LMS_CURL"
s = load_schema(cli="$LMCURL_BIN");
p = _lmcode_ s;
let h = curl.session("http://127.0.0.1:$SAML_PORT").header("Content-Type", "application/json");
let r1 = h.get("/ping").send();
assert_eq(r1.status(), 200);
assert_eq(r1.json("$.result").value(), "PONG");

let r2 = h.get("/idp/metadata").send();
assert_eq(r2.status(), 200);
assert(str_contains(r2.body(), "IDPSSODescriptor"));

let r3 = h.put("/users/carol").body("{\"email\":\"carol@example.com\",\"password\":\"carol-pass\",\"common_name\":\"Carol Danvers\"}").send();
assert_eq(r3.status(), 200);

let r4 = h.post("/assertion").body("{\"user\":\"carol\"}").send();
assert_eq(r4.status(), 200);
let b64 = r4.json("$.saml_response_b64").value();

let r5 = h.post("/verify").body("{\"saml_response_b64\":\"" + b64 + "\"}").send();
assert_eq(r5.status(), 200);
assert_eq(json_parse(r5.body()).get("valid").as_bool(), true);
assert_eq(r5.json("$.subject").value(), "carol@example.com");
end _lmcode_
res = run_lmcode(p);
assert(res.ok, "lmcurl SAML test failed: " + json_stringify(res));
EOF
    PATH="$(dirname "$LMCURL_BIN"):$PATH" lmscript "$LMS_CURL"
    echo "OK"
else
    echo "SKIP: lmcurl or lmscript not found"
fi

echo "=========================================================="
echo "TEST SECTION 6: lmcode Host, Batch & Std REST/CLI"
echo "=========================================================="

echo -n "Test 6.1: lmsaml --version... "
VER=$("$SERVER_BIN" --version)
echo "$VER" | grep -q "lmsaml 0.1.0" || { echo "FAIL ($VER)"; exit 1; }
echo "OK ($VER)"

echo -n "Test 6.2: lmsaml --lmcode-schema --json... "
"$SERVER_BIN" --lmcode-schema --json | python3 -c '
import json, sys
s = json.load(sys.stdin)
assert s["name"] == "lmsaml"
assert "Saml" in s["types"]
assert "Batch" in s["types"]
assert "RestExchange" in s["types"]
assert "RestGet" in s["interfaces"]
assert "CliCommand" in s["interfaces"]
'
echo "OK"

echo -n "Test 6.3: lmsaml --lmcode-signatures... "
SIG_COUNT=$("$SERVER_BIN" --lmcode-signatures | wc -l)
if [ "$SIG_COUNT" -lt 240 ]; then
    echo "FAIL: expected >= 240 signatures, got $SIG_COUNT"
    exit 1
fi
echo "OK ($SIG_COUNT signatures)"

if command -v lmscript >/dev/null 2>&1; then
    echo -n "Test 6.4: lmscript execution of Saml batch, assertions & std REST/CLI via _lmcode_... "
    LMS_HOST="$TEST_DIR/test_host.lms"
    cat << EOF > "$LMS_HOST"
s = load_schema(cli="$SERVER_BIN");
p = _lmcode_ s;
@"--org"
fn opt_org(x: RestExchange) -> void implements CliOption {
  x.set("org", x.query("org"));
}

@"enroll"
fn cmd_enroll(x: RestExchange) -> void implements CliCommand {
  let u = x.query("user");
  saml.add_user(u, "{\"email\":\"" + u + "@example.com\",\"password\":\"pw123\",\"common_name\":\"" + u + "\"}");
  let issued = saml.issue_assertion(u, "");
  let verified = saml.verify_assertion(json_parse(issued).get("saml_response_b64").as_string());
  x.send("enrolled:" + u + ":valid=" + str(json_parse(verified).get("valid").as_bool()));
}

@"/sso-user/:name"
fn get_sso_user(x: RestExchange) -> void implements RestGet {
  x.json(saml.get_user(x.param("name")));
}

let b = saml.batch();
b.ping().add_user("frank", "{\"email\":\"frank@example.com\",\"password\":\"frankpw\"}").get_user("frank");
let bres = b.exec();
print("BATCH_OUT:" + bres);

rest_config("session", "global");
print("CLI_OUT:" + rest_cli(str_split("--org=acme enroll --user=grace", " ")));
print("GET_OUT:" + rest_cli(str_split("/sso-user/grace", " ")));
end _lmcode_
r = run_lmcode(p);
assert(r.ok, "run_lmcode failed: " + json_stringify(r));
EOF
    LMS_OUT=$(SAML_PORT="$SAML_PORT" lmscript "$LMS_HOST")
    echo "$LMS_OUT" | grep -q 'frank@example.com' || { echo "FAIL batch ($LMS_OUT)"; exit 1; }
    echo "$LMS_OUT" | grep -q 'CLI_OUT:enrolled:grace:valid=true' || { echo "FAIL cli ($LMS_OUT)"; exit 1; }
    echo "$LMS_OUT" | grep -q 'grace@example.com' || { echo "FAIL get ($LMS_OUT)"; exit 1; }
    echo "OK"
fi

echo "=========================================================="
echo "All lmsaml integration tests passed successfully!"
echo "=========================================================="
