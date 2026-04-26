#!/bin/bash
echo "==== Token Lifetime Monitoring Test ===="
echo ""
echo "This test will monitor a disabled user's token over time"
echo ""

# Source admin credentials
source /etc/kolla/admin-openrc.sh

# Step 1: Create test user
echo "[1] Creating test user 'tokentest1'..."
openstack user create \
  --domain default \
  --password openstack \
  --email tokentest@example.com \
  tokentest1
openstack role add --user tokentest1 --project admin member
echo "User created"

# Step 2: Get token
echo ""
echo "[2] Getting token for tokentest1..."
ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD
ADMIN_PROJECT=$OS_PROJECT_NAME
ADMIN_AUTH_URL=$OS_AUTH_URL

export OS_USERNAME=tokentest1
export OS_PASSWORD='openstack'
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000

TEST_TOKEN=$(openstack token issue -f value -c id)
TOKEN_EXPIRES=$(openstack token issue -f value -c expires)
echo "Token: ${TEST_TOKEN:0:40}..."
echo "Expires: $TOKEN_EXPIRES"

# Save token for later testing
echo "$TEST_TOKEN" > token-for-lifetime-test.txt
echo "$TOKEN_EXPIRES" >> token-for-lifetime-test.txt

# Step 3: Test initial access
echo ""
echo "[3] Testing initial access..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $TEST_TOKEN" \
  http://192.168.100.11:9292/v2/images)
echo "Initial HTTP Status: $HTTP_CODE"

# Step 4: Disable user
echo ""
echo "[4] Disabling user..."
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=$ADMIN_PROJECT
export OS_AUTH_URL=$ADMIN_AUTH_URL

openstack user set --disable tokentest1
ENABLED=$(openstack user show tokentest1 -f value -c enabled)
echo "User enabled: $ENABLED"

# Step 5: Immediate test after disable
echo ""
echo "[5] Testing IMMEDIATELY after disable..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $TEST_TOKEN" \
  http://192.168.100.11:9292/v2/images)
echo "Immediate Status: $HTTP_CODE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

# Step 6: Wait and test periodically
echo ""
echo "[6] Monitoring token validity over time..."
echo "Testing every 2 minutes for 10 minutes..."
echo ""

for i in {1..5}; do
    WAIT_TIME=$((i * 2))
    echo "--- Test $i (after $WAIT_TIME minutes) ---"
    echo "Waiting 2 minutes..."
    sleep 120  # Wait 2 minutes
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "X-Auth-Token: $TEST_TOKEN" \
      http://192.168.100.11:9292/v2/images)
    
    echo "Time: $(date '+%H:%M:%S')"
    echo "HTTP Status: $HTTP_CODE"
    
    if [ "$HTTP_CODE" != "200" ]; then
        echo "Token INVALIDATED after $WAIT_TIME minutes!"
        break
    else
        echo "Token STILL valid after $WAIT_TIME minutes"
    fi
    echo ""
done

# Save results
echo ""
echo "[7] Saving test results..."
cat > ../token-lifetime-results.txt << RESULTS
Token Lifetime Test Results
============================
Test Date: $(date)
Token Created: $(date)
Token Expires: $TOKEN_EXPIRES

User Disabled At: $(date)

Token Status After Disable:
- Immediate: $HTTP_CODE
- After monitoring: See above

Conclusion:
$(if [ "$HTTP_CODE" = "200" ]; then echo "Token remained valid for tested duration"; else echo "Token was invalidated"; fi)
RESULTS

# Cleanup
echo ""
echo "[8] Cleanup..."
source /etc/kolla/admin-openrc.sh
openstack user delete tokentest1
echo "Test user deleted"

echo ""
echo "=== Test Complete ==="
echo "Results saved to: ../token-lifetime-results.txt"
echo ""
echo "If token still valid after 10 minutes, you can re-test with saved token:"
echo "  TOKEN=\$(head -1 token-for-lifetime-test.txt)"
echo "  curl -H \"X-Auth-Token: \$TOKEN\" http://192.168.100.11:9292/v2/images"
