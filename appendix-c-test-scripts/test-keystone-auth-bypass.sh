#!/bin/bash

echo "==== Keystone Authentication Bypass Tests ===="
echo ""

KEYSTONE_API="http://192.168.100.11:5000"
RESULTS_FILE="/tmp/auth-bypass-results.txt"
> $RESULTS_FILE

ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD

# ============================================================
# TEST 1: SQL Injection in Username Field
# ============================================================
echo "[TEST 1] SQL Injection in Username..."
echo ""

# Common SQL injection payloads
SQLI_PAYLOADS=(
    "admin'--"
    "admin' OR '1'='1"
    "admin' OR '1'='1'--"
    "' OR 1=1--"
    "admin'; DROP TABLE users;--"
    "admin' UNION SELECT NULL--"
    "' OR ''='"
    "admin'/*"
)

for payload in "${SQLI_PAYLOADS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$KEYSTONE_API/v3/auth/tokens" \
        -H "Content-Type: application/json" \
        -d "{
            \"auth\": {
                \"identity\": {
                    \"methods\": [\"password\"],
                    \"password\": {
                        \"user\": {
                            \"name\": \"$payload\",
                            \"password\": \"anything\",
                            \"domain\": {\"name\": \"Default\"}
                        }
                    }
                }
            }
        }")

    echo "Payload: $payload -> HTTP $HTTP_CODE"
    echo "TEST1|$payload|$HTTP_CODE" >> $RESULTS_FILE

    # 200 or 201 means auth succeeded - CRITICAL!
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        echo "CRITICAL: SQL INJECTION WORKED!"
        echo "   Payload: $payload"
    fi
done

echo ""

# ============================================================
# TEST 2: SQL Injection in Password Field
# ============================================================
echo "[TEST 2] SQL Injection in Password..."
echo ""

PASSWORD_PAYLOADS=(
    "' OR '1'='1"
    "' OR 1=1--"
    "anything' OR '1'='1"
    "x' OR 'x'='x"
)

for payload in "${PASSWORD_PAYLOADS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$KEYSTONE_API/v3/auth/tokens" \
        -H "Content-Type: application/json" \
        -d "{
            \"auth\": {
                \"identity\": {
                    \"methods\": [\"password\"],
                    \"password\": {
                        \"user\": {
                            \"name\": \"admin\",
                            \"password\": \"$payload\",
                            \"domain\": {\"name\": \"Default\"}
                        }
                    }
                }
            }
        }")

    echo "Payload: $payload -> HTTP $HTTP_CODE"
    echo "TEST2|$payload|$HTTP_CODE" >> $RESULTS_FILE

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        echo "CRITICAL: SQL INJECTION IN PASSWORD WORKED!"
    fi
done

echo ""

# ============================================================
# TEST 3: SQL Injection in Domain Field
# ============================================================
echo "[TEST 3] SQL Injection in Domain..."
echo ""

DOMAIN_PAYLOADS=(
    "Default' OR '1'='1"
    "' OR 1=1--"
    "Default'--"
)

for payload in "${DOMAIN_PAYLOADS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$KEYSTONE_API/v3/auth/tokens" \
        -H "Content-Type: application/json" \
        -d "{
            \"auth\": {
                \"identity\": {
                    \"methods\": [\"password\"],
                    \"password\": {
                        \"user\": {
                            \"name\": \"admin\",
                            \"password\": \"openstack\",
                            \"domain\": {\"name\": \"$payload\"}
                        }
                    }
                }
            }
        }")

    echo "Payload: $payload -> HTTP $HTTP_CODE"
    echo "TEST3|$payload|$HTTP_CODE" >> $RESULTS_FILE

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        echo "CRITICAL: SQL INJECTION IN DOMAIN WORKED!"
    fi
done

echo ""

# ============================================================
# TEST 4: Authentication Bypass via Empty Credentials
# ============================================================
echo "[TEST 4] Empty/Null Credential Tests..."
echo ""

# Empty username
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"","password":"","domain":{"name":"Default"}}}}}}')
echo "Empty username+password: HTTP $HTTP_CODE"
echo "TEST4|empty_creds|$HTTP_CODE" >> $RESULTS_FILE

# Null values
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":null,"password":null,"domain":{"name":"Default"}}}}}}')
echo "Null username+password: HTTP $HTTP_CODE"
echo "TEST4|null_creds|$HTTP_CODE" >> $RESULTS_FILE

# Missing password field entirely
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","domain":{"name":"Default"}}}}}}')
echo "Missing password field: HTTP $HTTP_CODE"
echo "TEST4|missing_password|$HTTP_CODE" >> $RESULTS_FILE

# Missing identity block
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{}}')
echo "Empty auth block: HTTP $HTTP_CODE"
echo "TEST4|empty_auth|$HTTP_CODE" >> $RESULTS_FILE

echo ""

# ============================================================
# TEST 5: Authentication Method Manipulation
# ============================================================
echo "[TEST 5] Auth Method Manipulation..."
echo ""

# Try using non-existent auth method
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":["bypass"],"bypass":{"user":{"name":"admin"}}}}}')
echo "Fake 'bypass' method: HTTP $HTTP_CODE"
echo "TEST5|fake_method|$HTTP_CODE" >> $RESULTS_FILE

# Try empty methods array
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":[],"password":{"user":{"name":"admin","password":"openstack","domain":{"name":"Default"}}}}}}')
echo "Empty methods array: HTTP $HTTP_CODE"
echo "TEST5|empty_methods|$HTTP_CODE" >> $RESULTS_FILE

# Try multiple methods with one valid
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d '{"auth":{"identity":{"methods":["password","token"],"password":{"user":{"name":"admin","password":"wrong_password","domain":{"name":"Default"}}},"token":{"id":"fake_token_value"}}}}')
echo "Mixed methods (both invalid): HTTP $HTTP_CODE"
echo "TEST5|mixed_methods|$HTTP_CODE" >> $RESULTS_FILE

echo ""

# ============================================================
# TEST 6: Project/Scope Manipulation
# ============================================================
echo "[TEST 6] Project/Scope Manipulation..."
echo ""

# Get valid token first
TOKEN=$(openstack token issue -f value -c id)

# Request token scoped to non-existent project
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d "{
        \"auth\": {
            \"identity\": {
                \"methods\": [\"token\"],
                \"token\": {\"id\": \"$TOKEN\"}
            },
            \"scope\": {
                \"project\": {
                    \"name\": \"nonexistent-project-xyzabc\",
                    \"domain\": {\"name\": \"Default\"}
                }
            }
        }
    }")
echo "Scope to non-existent project: HTTP $HTTP_CODE"
echo "TEST6|nonexist_project|$HTTP_CODE" >> $RESULTS_FILE

# Request token scoped to another tenant's project without permission
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYSTONE_API/v3/auth/tokens" \
    -H "Content-Type: application/json" \
    -d "{
        \"auth\": {
            \"identity\": {
                \"methods\": [\"token\"],
                \"token\": {\"id\": \"$TOKEN\"}
            },
            \"scope\": {
                \"domain\": {
                    \"name\": \"nonexistent-domain-xyzabc\"
                }
            }
        }
    }")
echo "Scope to non-existent domain: HTTP $HTTP_CODE"
echo "TEST6|nonexist_domain|$HTTP_CODE" >> $RESULTS_FILE

echo ""

# ============================================================
# TEST 7: Brute Force / Rate Limiting Test
# ============================================================
echo "[TEST 7] Rate Limiting Test..."
echo ""
echo "Sending 20 rapid auth attempts with wrong password..."

BLOCKED="NO"
for i in $(seq 1 20); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$KEYSTONE_API/v3/auth/tokens" \
        -H "Content-Type: application/json" \
        -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"admin","password":"wrong_password_'$i'","domain":{"name":"Default"}}}}}}')

    if [ "$HTTP_CODE" = "429" ] || [ "$HTTP_CODE" = "503" ]; then
        echo "Rate limited at attempt $i (HTTP $HTTP_CODE)"
        BLOCKED="YES"
        break
    fi

    echo "Attempt $i: HTTP $HTTP_CODE"
done

if [ "$BLOCKED" = "NO" ]; then
    echo "WARNING: No rate limiting detected after 20 attempts!"
    echo "TEST7|rate_limit|NOT_ENFORCED" >> $RESULTS_FILE
else
    echo "Rate limiting is active"
    echo "TEST7|rate_limit|ENFORCED" >> $RESULTS_FILE
fi

echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "========================================="
echo "       AUTH BYPASS TEST SUMMARY"
echo "========================================="
echo ""
echo "Results file: $RESULTS_FILE"
echo ""

# Count results
TOTAL=$(wc -l < $RESULTS_FILE)
VULN_COUNT=$(grep -cE "\|20[01]\b" $RESULTS_FILE || echo 0)
echo "Total tests: $TOTAL"
echo "Vulnerabilities found: $VULN_COUNT"
echo ""

# Show any 200/201 results (vulnerabilities)
if [ "$VULN_COUNT" -gt 0 ]; then
    echo "VULNERABILITIES FOUND:"
    grep -E "\|20[01]\b" $RESULTS_FILE
else
    echo "No authentication bypass vulnerabilities found"
fi

echo ""
echo "Rate Limiting: $(grep 'rate_limit' $RESULTS_FILE | cut -d'|' -f3)"
echo ""
echo "=== Auth Bypass Tests Complete ==="
