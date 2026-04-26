#!/bin/bash
echo "==== Testing Disabled User Token Persistence ===="
echo ""

# Source admin credentials first
source /etc/kolla/admin-openrc.sh

# Step 1: Create a test user
echo "[1] Creating a test user 'vulntest1'..."
openstack user create \
  --domain default \
  --password openstack \
  --email vulntest@example.com \
  vulntest1

# Assign member role
openstack role add --user vulntest1 --project admin member
echo "User created"
openstack user show vulntest1

# Step 2: Get a token for that user
echo ""
echo "[2] Getting token for vulntest1..."
# Save current admin env
ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD
ADMIN_PROJECT=$OS_PROJECT_NAME
ADMIN_AUTH_URL=$OS_AUTH_URL

# Switch to test user
export OS_USERNAME=vulntest1
export OS_PASSWORD='openstack'
export OS_PROJECT_NAME=admin
export OS_AUTH_URL=http://192.168.100.11:5000
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3

TEST_TOKEN=$(openstack token issue -f value -c id)
echo "Token obtained: ${TEST_TOKEN:0:30}..."

# Step 3: Token works
echo ""
echo "[3] Testing token before disabling user..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $TEST_TOKEN" \
  http://192.168.100.11:9292/v2/images)
echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "Token works as expected"
else
    echo "Token doesn't work - something wrong (HTTP $HTTP_CODE)"
    echo "This may indicate the user needs additional permissions"
    # Continue anyway for testing
fi

# Step 4: Switch back to admin and disable user
echo ""
echo "[4] DISABLING user vulntest1..."
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=$ADMIN_PROJECT
export OS_AUTH_URL=$ADMIN_AUTH_URL

openstack user set --disable vulntest1

# Verify disabled
ENABLED=$(openstack user show vulntest1 -f value -c enabled)
echo "User enabled status: $ENABLED"

# Step 5: Test if token STILL works AFTER disabling
echo ""
echo "[5] Testing if token works after disabling user..."
echo "If this returns 200, it's vulnerable"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $TEST_TOKEN" \
  http://192.168.100.11:9292/v2/images)
echo "HTTP Status: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "VULNERABILITY FOUND"
    echo "Severity: HIGH"
    echo "Impact: Disabled user tokens remain valid"
    echo "Risk: Accounts cannot be immediately disabled in emergency"
    VULN_FOUND="YES"
elif [ "$HTTP_CODE" = "401" ]; then
    echo "SECURE: Token properly invalidated"
    echo "Status: $HTTP_CODE (token rejected)"
    VULN_FOUND="NO"
else
    echo "UNKNOWN: Unexpected status code $HTTP_CODE"
    VULN_FOUND="UNKNOWN"
fi

# STEP 6: Try to get NEW token with disabled user
echo ""
echo "[6] Attempting to get NEW token with disabled account..."
export OS_USERNAME=vulntest1
export OS_PASSWORD='openstack'
export OS_PROJECT_NAME=admin

if openstack token issue 2>/dev/null; then
    echo "Vulnerability: Can still get new tokens"
else
    echo "SECURE: Cannot get new tokens (as expected)"
fi

# Cleanup
echo ""
echo "[7] Cleanup..."
source /etc/kolla/admin-openrc.sh
openstack user delete vulntest1
echo "Test user deleted"
echo ""
echo "=== Test Completed ==="
echo "Vulnerability Found: $VULN_FOUND"
