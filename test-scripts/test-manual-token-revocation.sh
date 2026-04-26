#!/bin/bash

echo "==== Manual Token Revocation Test ===="
echo ""
echo "Testing if 'openstack token revoke' bypasses the cache"
echo ""

# Source admin credentials first
source /etc/kolla/admin-openrc.sh

# Step 1: Create test user
echo "[1] Creating test user 'revoketest1'..."
openstack user create \
  --domain default \
  --password openstack \
  --email revoketest@example.com \
  revoketest1

openstack role add --user revoketest1 --project admin member
echo "User created"

# Step 2: Get token and save token ID
echo ""
echo "[2] Getting token for revoketest1..."
ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD
ADMIN_PROJECT=$OS_PROJECT_NAME
ADMIN_AUTH_URL=$OS_AUTH_URL

export OS_USERNAME=revoketest1
export OS_PASSWORD='openstack'
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000

# Get full token info
TOKEN_INFO=$(openstack token issue -f json)
TOKEN_ID=$(echo "$TOKEN_INFO" | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")
TOKEN_EXPIRES=$(echo "$TOKEN_INFO" | python3 -c "import sys, json; print(json.load(sys.stdin)['expires'])")

echo "Token ID: ${TOKEN_ID:0:40}..."
echo "Expires: $TOKEN_EXPIRES"

# Step 3: Test token works
echo ""
echo "[3] Testing token works BEFORE revocation..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $TOKEN_ID" \
  http://192.168.100.11:9292/v2/images)
echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" != "200" ]; then
    echo "ERROR: Token doesn't work initially - something wrong!"
    echo "This may indicate the user needs additional permissions"
    # Continue anyway to test revocation
fi

# Step 4: Manually revoke the token
echo ""
echo "[4] Manually revoking token with 'openstack token revoke'..."
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=$ADMIN_PROJECT
export OS_AUTH_URL=$ADMIN_AUTH_URL

echo "Command: openstack token revoke $TOKEN_ID"
openstack token revoke $TOKEN_ID

if [ $? -eq 0 ]; then
    echo "Revoke command succeeded"
else
    echo "WARNING: Revoke command failed or returned error"
fi

# Step 5: Test IMMEDIATELY after revocation
echo ""
echo "[5] Testing token IMMEDIATELY after manual revocation..."
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $TOKEN_ID" \
  http://192.168.100.11:9292/v2/images)

echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "Token invalidated (status: $HTTP_CODE)"
    if [ "$HTTP_CODE" = "401" ]; then
        echo "   Manual revocation may have bypassed cache OR token was already invalid"
    fi
    IMMEDIATE_REVOKE="INVALIDATED"
else
    echo "WARNING: Token still works after revocation (status: $HTTP_CODE)"
    echo "   Manual revocation does NOT bypass cache"
    IMMEDIATE_REVOKE="NO"
fi

# Step 6: Wait and test again (if token still worked)
if [ "$HTTP_CODE" = "200" ]; then
    echo ""
    echo "[6] Token still worked, testing every 30 seconds for 3 minutes..."

    for i in {1..6}; do
        echo ""
        echo "--- Test $i (after $((i*30)) seconds) ---"
        sleep 30

        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
          -H "X-Auth-Token: $TOKEN_ID" \
          http://192.168.100.11:9292/v2/images)

        echo "Time: $(date '+%H:%M:%S')"
        echo "HTTP Status: $HTTP_CODE"

        if [ "$HTTP_CODE" != "200" ]; then
            echo "Token invalidated after $((i*30)) seconds"
            break
        fi
    done
fi

# Step 7: Compare with disable method
echo ""
echo "[7] Comparison Test: Disable user method..."
echo "Creating second user to compare..."

source /etc/kolla/admin-openrc.sh

openstack user create \
  --domain default \
  --password openstack \
  disabletest1 > /dev/null 2>&1

openstack role add --user disabletest1 --project admin member > /dev/null 2>&1

export OS_USERNAME=disabletest1
export OS_PASSWORD='openstack'
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000

DISABLE_TOKEN=$(openstack token issue -f value -c id)

source /etc/kolla/admin-openrc.sh

# Disable the user
openstack user set --disable disabletest1

# Test immediately
HTTP_CODE_DISABLE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $DISABLE_TOKEN" \
  http://192.168.100.11:9292/v2/images)

echo "Disable method immediate status: $HTTP_CODE_DISABLE"

# Cleanup
openstack user delete disabletest1 > /dev/null 2>&1

# Step 8: Results summary
echo ""
echo "========================================="
echo "           RESULTS SUMMARY"
echo "========================================="
echo ""
echo "Method 1 - Manual Token Revocation:"
echo "  Command: openstack token revoke <token>"
echo "  Immediate Effect: $IMMEDIATE_REVOKE"
echo ""
echo "Method 2 - User Disable:"
echo "  Command: openstack user set --disable"
echo "  Immediate Effect: $([ "$HTTP_CODE_DISABLE" = "200" ] && echo "NO (cache delay)" || echo "YES (immediate)")"
echo ""

if [ "$IMMEDIATE_REVOKE" = "YES" ]; then
    echo "CONCLUSION: Manual token revocation is EFFECTIVE"
    echo "   and bypasses the validation cache!"
    echo ""
    echo "RECOMMENDATION:"
    echo "   When disabling accounts for security reasons,"
    echo "   also manually revoke active tokens:"
    echo ""
    echo "   openstack token revoke <token-id>"
    echo ""
else
    echo "NOTE: Results depend on initial token validity"
    echo "   Compare revoke vs disable methods above"
fi

# Cleanup
echo ""
echo "[8] Cleanup..."
source /etc/kolla/admin-openrc.sh
openstack user delete revoketest1
echo "Test user deleted"

echo ""
echo "=== Test Complete ==="
