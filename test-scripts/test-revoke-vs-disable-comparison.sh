#!/bin/bash
echo "==== Revoke vs Disable: Side-by-Side Comparison ===="
echo ""

# Source admin credentials
source /etc/kolla/admin-openrc.sh

# Create TWO users simultaneously
echo "[1] Creating two test users..."
openstack user create --domain default --password openstack revoke_user
openstack user create --domain default --password openstack disable_user
openstack role add --user revoke_user --project admin member
openstack role add --user disable_user --project admin member
echo "Both users created"

# Get tokens for BOTH users
echo ""
echo "[2] Getting tokens for both users..."
ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD
ADMIN_PROJECT=$OS_PROJECT_NAME
ADMIN_AUTH_URL=$OS_AUTH_URL

# Token 1: For revocation
export OS_USERNAME=revoke_user
export OS_PASSWORD=openstack
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000

REVOKE_TOKEN=$(openstack token issue -f value -c id)
echo "Revoke test token: ${REVOKE_TOKEN:0:30}..."

# Token 2: For user disable
export OS_USERNAME=disable_user
export OS_PASSWORD=openstack
export OS_PROJECT_NAME=admin

DISABLE_TOKEN=$(openstack token issue -f value -c id)
echo "Disable test token: ${DISABLE_TOKEN:0:30}..."

# Switch back to admin
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=$ADMIN_PROJECT
export OS_AUTH_URL=$ADMIN_AUTH_URL

# Test both tokens work
echo ""
echo "[3] Testing both tokens work initially..."
HTTP1=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Auth-Token: $REVOKE_TOKEN" http://192.168.100.11:9292/v2/images)
HTTP2=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Auth-Token: $DISABLE_TOKEN" http://192.168.100.11:9292/v2/images)
echo "Revoke token: $HTTP1"
echo "Disable token: $HTTP2"

# Perform actions AT THE SAME TIME
echo ""
echo "[4] Performing revoke and disable simultaneously..."
echo "Time: $(date '+%H:%M:%S')"
openstack token revoke $REVOKE_TOKEN &
openstack user set --disable disable_user &
wait
echo "Both actions completed"

# Test IMMEDIATELY
echo ""
echo "[5] Testing IMMEDIATELY after (< 1 second)..."
START_TIME=$(date '+%s')
HTTP_REVOKE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Auth-Token: $REVOKE_TOKEN" http://192.168.100.11:9292/v2/images)
HTTP_DISABLE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Auth-Token: $DISABLE_TOKEN" http://192.168.100.11:9292/v2/images)
echo "Revoke method: $HTTP_REVOKE"
echo "Disable method: $HTTP_DISABLE"

# Monitor over time
echo ""
echo "[6] Monitoring both tokens every 30 seconds..."
for i in {1..10}; do
    sleep 30
    ELAPSED=$(( $(date '+%s') - START_TIME ))
    
    HTTP_REVOKE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Auth-Token: $REVOKE_TOKEN" http://192.168.100.11:9292/v2/images)
    HTTP_DISABLE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Auth-Token: $DISABLE_TOKEN" http://192.168.100.11:9292/v2/images)
    
    echo "After ${ELAPSED}s - Revoke: $HTTP_REVOKE | Disable: $HTTP_DISABLE"
    
    # Stop if both invalid
    if [ "$HTTP_REVOKE" != "200" ] && [ "$HTTP_DISABLE" != "200" ]; then
        echo "Both tokens invalidated"
        break
    fi
done

# Summary
echo ""
echo "========================================="
echo "           COMPARISON RESULTS"
echo "========================================="
echo ""
echo "Both methods tested under identical conditions"
echo "at the exact same time."
echo ""

# Cleanup
echo "Cleaning up..."
openstack user delete revoke_user disable_user
echo ""
echo "=== Test Complete ==="
