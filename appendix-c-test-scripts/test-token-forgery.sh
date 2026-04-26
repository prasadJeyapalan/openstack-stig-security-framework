#!/bin/bash

echo "==== Keystone Token Manipulation & Forgery Tests ===="
echo ""

KEYSTONE_API="http://192.168.100.11:5000"
GLANCE_API="http://192.168.100.11:9292"
RESULTS_FILE="/tmp/token-forgery-results.txt"
> $RESULTS_FILE

source /etc/kolla/admin-openrc.sh

ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD

# Get a legitimate token for reference
VALID_TOKEN=$(openstack token issue -f value -c id)
echo "Valid token obtained: ${VALID_TOKEN:0:40}..."
echo ""

# ============================================================
# TEST 1: Completely Fake Token
# ============================================================
echo "[TEST 1] Completely Fake/Random Token..."
echo ""

FAKE_TOKENS=(
    "completely_fake_token_12345"
    "gAAAAABfaketoken000000000000000000000000000000000000000000"
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    "admin_token"
    ""
)

for token in "${FAKE_TOKENS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Auth-Token: $token" \
        "$GLANCE_API/v2/images")

    echo "Token: '${token:0:50}...' -> HTTP $HTTP_CODE"
    echo "TEST1|${token:0:30}|$HTTP_CODE" >> $RESULTS_FILE

    if [ "$HTTP_CODE" = "200" ]; then
        echo "CRITICAL: Fake token accepted!"
    fi
done

echo ""

# ============================================================
# TEST 2: Token Prefix Manipulation
# ============================================================
echo "[TEST 2] Token Prefix/Structure Manipulation..."
echo ""

# Valid token starts with "gAAAAA" (Fernet format)
# Try manipulating parts of a valid token

# Truncated token
TRUNCATED="${VALID_TOKEN:0:50}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $TRUNCATED" \
    "$GLANCE_API/v2/images")
echo "Truncated token (50 chars): HTTP $HTTP_CODE"
echo "TEST2|truncated|$HTTP_CODE" >> $RESULTS_FILE

# Token with extra characters appended
EXTENDED="${VALID_TOKEN}AAAAAAAAAAA"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $EXTENDED" \
    "$GLANCE_API/v2/images")
echo "Extended token (extra chars): HTTP $HTTP_CODE"
echo "TEST2|extended|$HTTP_CODE" >> $RESULTS_FILE

# Token with one character flipped
FLIPPED=$(echo "$VALID_TOKEN" | sed 's/A/B/1')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $FLIPPED" \
    "$GLANCE_API/v2/images")
echo "Flipped char token: HTTP $HTTP_CODE"
echo "TEST2|flipped|$HTTP_CODE" >> $RESULTS_FILE

# Token with prefix replaced
REPLACED="gBBBBB${VALID_TOKEN:6}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $REPLACED" \
    "$GLANCE_API/v2/images")
echo "Replaced prefix token: HTTP $HTTP_CODE"
echo "TEST2|replaced_prefix|$HTTP_CODE" >> $RESULTS_FILE

echo ""

# ============================================================
# TEST 3: Replay Original Token via Different Headers
# ============================================================
echo "[TEST 3] Token Header Manipulation..."
echo ""

# Standard header
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $VALID_TOKEN" \
    "$GLANCE_API/v2/images")
echo "Standard X-Auth-Token: HTTP $HTTP_CODE"
echo "TEST3|standard_header|$HTTP_CODE" >> $RESULTS_FILE

# Try Authorization Bearer (JWT style)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $VALID_TOKEN" \
    "$GLANCE_API/v2/images")
echo "Authorization Bearer: HTTP $HTTP_CODE"
echo "TEST3|bearer_header|$HTTP_CODE" >> $RESULTS_FILE

# Try lowercase header
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -h "x-auth-token: $VALID_TOKEN" \
    "$GLANCE_API/v2/images")
echo "Lowercase x-auth-token: HTTP $HTTP_CODE"
echo "TEST3|lowercase_header|$HTTP_CODE" >> $RESULTS_FILE

# Try X-Auth-Token AND Authorization both
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $VALID_TOKEN" \
    -H "Authorization: Bearer fake_token_here" \
    "$GLANCE_API/v2/images")
echo "Both headers (valid + fake): HTTP $HTTP_CODE"
echo "TEST3|both_headers|$HTTP_CODE" >> $RESULTS_FILE

# Try token in query parameter
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$GLANCE_API/v2/images?token=$VALID_TOKEN")
echo "Token as query parameter: HTTP $HTTP_CODE"
echo "TEST3|query_param|$HTTP_CODE" >> $RESULTS_FILE

echo ""

# ============================================================
# TEST 4: Token Scope Escalation
# ============================================================
echo "[TEST 4] Token Scope Escalation..."
echo ""

# Create a low-privilege user
openstack user create --domain default --password openstack scopetest1 > /dev/null 2>&1
openstack project create scopetest-project > /dev/null 2>&1
openstack role add --user scopetest1 --project scopetest-project member > /dev/null 2>&1

# Get token for low-privilege user
export OS_USERNAME=scopetest1
export OS_PASSWORD=openstack
export OS_PROJECT_NAME=scopetest-project
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_AUTH_URL=http://192.168.100.11:5000/v3
export OS_IDENTITY_API_VERSION=3

LOW_TOKEN=$(openstack token issue -f value -c id)
echo "Low-privilege token: ${LOW_TOKEN:0:40}..."

# Test: Can low-privilege token access admin endpoints?
echo ""
echo "Testing low-privilege token against admin endpoints..."

# Try to list all users (admin only)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $LOW_TOKEN" \
    "$KEYSTONE_API/v3/users")
echo "List all users: HTTP $HTTP_CODE"
echo "TEST4|list_users|$HTTP_CODE" >> $RESULTS_FILE

# Try to list all projects
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $LOW_TOKEN" \
    "$KEYSTONE_API/v3/projects")
echo "List all projects: HTTP $HTTP_CODE"
echo "TEST4|list_projects|$HTTP_CODE" >> $RESULTS_FILE

# Try to create a user (admin only)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/users" \
    -H "X-Auth-Token: $LOW_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"user":{"name":"hacked_user","password":"hacked123","domain":{"name":"Default"}}}')
echo "Create user (admin only): HTTP $HTTP_CODE"
echo "TEST4|create_user|$HTTP_CODE" >> $RESULTS_FILE

# Try to delete admin user
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE "$KEYSTONE_API/v3/users/admin" \
    -H "X-Auth-Token: $LOW_TOKEN")
echo "Delete admin user: HTTP $HTTP_CODE"
echo "TEST4|delete_admin|$HTTP_CODE" >> $RESULTS_FILE

# Try to access other project's resources
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $LOW_TOKEN" \
    "$GLANCE_API/v2/images")
echo "Access Glance images: HTTP $HTTP_CODE"
echo "TEST4|glance_access|$HTTP_CODE" >> $RESULTS_FILE

# Cleanup
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=admin
openstack user delete scopetest1 > /dev/null 2>&1
openstack project delete scopetest-project > /dev/null 2>&1

echo ""

# ============================================================
# TEST 5: Fernet Token Structure Analysis
# ============================================================
echo "[TEST 5] Fernet Token Structure Analysis..."
echo ""

# Fernet tokens are base64 encoded - let's analyze structure
echo "Analyzing valid token structure..."
echo "Token length: ${#VALID_TOKEN}"
echo "Token prefix: ${VALID_TOKEN:0:6}"

# Decode the token to see structure
echo ""
echo "Attempting base64 decode of token..."
DECODED=$(echo "$VALID_TOKEN" | base64 -d 2>/dev/null | xxd | head -5)
echo "Decoded (hex):"
echo "$DECODED"

# Check if token contains readable fields
echo ""
echo "Scanning for readable strings in token..."
STRINGS=$(echo "$VALID_TOKEN" | base64 -d 2>/dev/null | strings 2>/dev/null)
if [ -n "$STRINGS" ]; then
    echo "Readable strings found:"
    echo "$STRINGS"
else
    echo "No readable strings (token is encrypted - GOOD)"
fi

echo ""

# ============================================================
# TEST 6: Token Replay Across Services
# ============================================================
echo "[TEST 6] Token Replay Across Services..."
echo ""

# Token obtained via Keystone - does it work on Glance?
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $VALID_TOKEN" \
    "$GLANCE_API/v2/images")
echo "Keystone token on Glance: HTTP $HTTP_CODE"
echo "TEST6|glance_replay|$HTTP_CODE" >> $RESULTS_FILE

# Does it work on Nova?
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $VALID_TOKEN" \
    "http://192.168.100.11:8774/v2.1/servers")
echo "Keystone token on Nova: HTTP $HTTP_CODE"
echo "TEST6|nova_replay|$HTTP_CODE" >> $RESULTS_FILE

# Does it work on Neutron?
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $VALID_TOKEN" \
    "http://192.168.100.11:9696/v2.0/networks")
echo "Keystone token on Neutron: HTTP $HTTP_CODE"
echo "TEST6|neutron_replay|$HTTP_CODE" >> $RESULTS_FILE

# Does it work on Horizon (web UI)?
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $VALID_TOKEN" \
    "http://192.168.100.11/dashboard")
echo "Keystone token on Horizon: HTTP $HTTP_CODE"
echo "TEST6|horizon_replay|$HTTP_CODE" >> $RESULTS_FILE

echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "========================================="
echo "     TOKEN FORGERY TEST SUMMARY"
echo "========================================="
echo ""

TOTAL=$(wc -l < $RESULTS_FILE)
VULN_200=$(grep -cE "\|200$" $RESULTS_FILE || echo 0)

echo "Total tests: $TOTAL"
echo ""

echo "--- Fake Token Tests ---"
grep "^TEST1" $RESULTS_FILE
echo ""

echo "--- Token Manipulation Tests ---"
grep "^TEST2" $RESULTS_FILE
echo ""

echo "--- Header Manipulation Tests ---"
grep "^TEST3" $RESULTS_FILE
echo ""

echo "--- Scope Escalation Tests ---"
grep "^TEST4" $RESULTS_FILE
echo ""

echo "--- Token Replay Tests ---"
grep "^TEST6" $RESULTS_FILE
echo ""

# Check for unexpected 200s
echo "========================================="
echo "Unexpected 200 responses (potential vulns):"
grep -E "\|200$" $RESULTS_FILE | grep -v "TEST3|standard_header" | grep -v "TEST6" | grep -v "TEST4|glance_access"
echo "========================================="

echo ""
echo "=== Token Forgery Tests Complete ==="
