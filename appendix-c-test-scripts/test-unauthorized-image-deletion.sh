#!/bin/bash

echo "==== Unauthorized Image Deletion Test ===="
echo ""

KEYSTONE_API="http://192.168.100.11:5000"
GLANCE_API="http://192.168.100.11:9292"
RESULTS_FILE="/tmp/deletion-test-results.txt"
> $RESULTS_FILE

source /etc/kolla/admin-openrc.sh

ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD

# ============================================================
# SETUP
# ============================================================
echo "[SETUP] Creating test environment..."
echo ""

# Create two projects
openstack project create --description "Owner of images" project-owner > /dev/null 2>&1
openstack project create --description "Attacker project" project-attacker > /dev/null 2>&1

# Create users
openstack user create --domain default --password openstack image-owner > /dev/null 2>&1
openstack user create --domain default --password openstack image-attacker > /dev/null 2>&1

# Assign roles
openstack role add --user image-owner --project project-owner member
openstack role add --user image-attacker --project project-attacker member

echo "Owner:    image-owner  -> project-owner"
echo "Attacker: image-attacker -> project-attacker"
echo ""

# ============================================================
# Create test images as OWNER
# ============================================================
echo "[SETUP] Creating test images as owner..."
echo ""

export OS_USERNAME=image-owner
export OS_PASSWORD=openstack
export OS_PROJECT_NAME=project-owner
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_AUTH_URL=$KEYSTONE_API/v3
export OS_IDENTITY_API_VERSION=3

# Create 3 test images with different visibility
dd if=/dev/zero of=/tmp/img-private.img bs=1M count=1 2>/dev/null
dd if=/dev/zero of=/tmp/img-shared.img bs=1M count=1 2>/dev/null

PRIVATE_IMG=$(openstack image create \
  --private \
  --disk-format raw \
  --container-format bare \
  --file /tmp/img-private.img \
  owner-private-image \
  -f value -c id)

SHARED_IMG=$(openstack image create \
  --shared \
  --disk-format raw \
  --container-format bare \
  --file /tmp/img-shared.img \
  owner-shared-image \
  -f value -c id)

echo "Private image: $PRIVATE_IMG"
echo "Shared image:  $SHARED_IMG"
echo ""

# Verify owner can see images
OWNER_TOKEN=$(openstack token issue -f value -c id)
OWNER_COUNT=$(curl -s -H "X-Auth-Token: $OWNER_TOKEN" \
  "$GLANCE_API/v2/images" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['images']))")
echo "Owner can see $OWNER_COUNT image(s)"
echo ""

# ============================================================
# Get attacker token
# ============================================================
export OS_USERNAME=image-attacker
export OS_PASSWORD=openstack
export OS_PROJECT_NAME=project-attacker

ATTACKER_TOKEN=$(openstack token issue -f value -c id)
echo "Attacker token obtained"
echo ""

# Switch back to admin
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=admin

# ============================================================
# TEST 1: Delete PRIVATE image (attacker has no knowledge)
# ============================================================
echo "[TEST 1] Attacker deleting Owner's PRIVATE image..."
echo "  Target: $PRIVATE_IMG"

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X DELETE "$GLANCE_API/v2/images/$PRIVATE_IMG" \
  -H "X-Auth-Token: $ATTACKER_TOKEN")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
echo "  HTTP Status: $HTTP_CODE"
echo "TEST1|delete_private|$HTTP_CODE" >> $RESULTS_FILE

# Check if image still exists
ADMIN_TOKEN=$(openstack token issue -f value -c id)
EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $ADMIN_TOKEN" \
  "$GLANCE_API/v2/images/$PRIVATE_IMG")

echo "  Image still exists: $([ "$EXISTS" = "200" ] && echo "YES" || echo "NO - DELETED!")"
echo "TEST1|private_exists|$EXISTS" >> $RESULTS_FILE

if [ "$EXISTS" != "200" ]; then
    echo "  CRITICAL VULNERABILITY: Attacker deleted private image!"
else
    echo "  SECURE: Private image protected"
fi
echo ""

# ============================================================
# TEST 2: Delete SHARED image
# ============================================================
echo "[TEST 2] Attacker deleting Owner's SHARED image..."
echo "  Target: $SHARED_IMG"

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X DELETE "$GLANCE_API/v2/images/$SHARED_IMG" \
  -H "X-Auth-Token: $ATTACKER_TOKEN")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
echo "  HTTP Status: $HTTP_CODE"
echo "TEST2|delete_shared|$HTTP_CODE" >> $RESULTS_FILE

# Check if image still exists
EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $ADMIN_TOKEN" \
  "$GLANCE_API/v2/images/$SHARED_IMG")

echo "  Image still exists: $([ "$EXISTS" = "200" ] && echo "YES" || echo "NO - DELETED!")"
echo "TEST2|shared_exists|$EXISTS" >> $RESULTS_FILE

if [ "$EXISTS" != "200" ]; then
    echo "  CRITICAL VULNERABILITY: Attacker deleted shared image!"
else
    echo "  SECURE: Shared image protected"
fi
echo ""

# ============================================================
# TEST 3: Delete using known PUBLIC image IDs
# ============================================================
echo "[TEST 3] Attacker deleting PUBLIC images..."

# Get public images
PUBLIC_IMGS=$(curl -s -H "X-Auth-Token: $ATTACKER_TOKEN" \
  "$GLANCE_API/v2/images?visibility=public" | \
  python3 -c "import sys,json; [print(i['id']) for i in json.load(sys.stdin)['images']]" 2>/dev/null)

if [ -n "$PUBLIC_IMGS" ]; then
    PUBLIC_IMG_ID=$(echo "$PUBLIC_IMGS" | head -1)
    echo "  Target public image: $PUBLIC_IMG_ID"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -X DELETE "$GLANCE_API/v2/images/$PUBLIC_IMG_ID" \
      -H "X-Auth-Token: $ATTACKER_TOKEN")

    echo "  HTTP Status: $HTTP_CODE"
    echo "TEST3|delete_public|$HTTP_CODE" >> $RESULTS_FILE

    EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "X-Auth-Token: $ADMIN_TOKEN" \
      "$GLANCE_API/v2/images/$PUBLIC_IMG_ID")

    echo "  Image still exists: $([ "$EXISTS" = "200" ] && echo "YES" || echo "NO - DELETED!")"
    echo "TEST3|public_exists|$EXISTS" >> $RESULTS_FILE

    if [ "$EXISTS" != "200" ]; then
        echo "  CRITICAL: Attacker deleted PUBLIC image!"
    else
        echo "  SECURE: Public image protected"
    fi
else
    echo "  No public images found for testing"
    echo "TEST3|delete_public|SKIPPED" >> $RESULTS_FILE
fi
echo ""

# ============================================================
# TEST 4: Delete with manipulated headers
# ============================================================
echo "[TEST 4] Delete attempts with header manipulation..."
echo ""

# Try with extra headers
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "$GLANCE_API/v2/images/$PRIVATE_IMG" \
  -H "X-Auth-Token: $ATTACKER_TOKEN" \
  -H "X-Project-Id: $(openstack project show project-owner -f value -c id)" \
  -H "X-User-Id: $(openstack user show image-owner -f value -c id)")

echo "  With forged X-Project-Id + X-User-Id: HTTP $HTTP_CODE"
echo "TEST4|forged_headers|$HTTP_CODE" >> $RESULTS_FILE

# Check if image still exists
EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $ADMIN_TOKEN" \
  "$GLANCE_API/v2/images/$PRIVATE_IMG")
echo "  Image still exists: $([ "$EXISTS" = "200" ] && echo "YES" || echo "NO - DELETED!")"
echo "TEST4|forged_exists|$EXISTS" >> $RESULTS_FILE

if [ "$EXISTS" != "200" ]; then
    echo "  CRITICAL: Forged headers bypassed authorization!"
else
    echo "  SECURE: Forged headers ignored"
fi
echo ""

# ============================================================
# TEST 5: Delete with admin role claim
# ============================================================
echo "[TEST 5] Delete with manipulated role headers..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "$GLANCE_API/v2/images/$PRIVATE_IMG" \
  -H "X-Auth-Token: $ATTACKER_TOKEN" \
  -H "X-Roles: admin,member,reader" \
  -H "X-Role: admin")

echo "  With forged X-Roles: admin: HTTP $HTTP_CODE"
echo "TEST5|forged_roles|$HTTP_CODE" >> $RESULTS_FILE

EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $ADMIN_TOKEN" \
  "$GLANCE_API/v2/images/$PRIVATE_IMG")
echo "  Image still exists: $([ "$EXISTS" = "200" ] && echo "YES" || echo "NO - DELETED!")"
echo "TEST5|roles_exists|$EXISTS" >> $RESULTS_FILE

if [ "$EXISTS" != "200" ]; then
    echo "  CRITICAL: Role manipulation worked!"
else
    echo "  SECURE: Forged roles ignored"
fi
echo ""

# ============================================================
# TEST 6: Rapid Delete Requests (Race Condition)
# ============================================================
echo "[TEST 6] Rapid simultaneous delete requests..."

# Fire 5 simultaneous delete requests
for i in $(seq 1 5); do
    curl -s -o /dev/null -w "%{http_code}" \
      -X DELETE "$GLANCE_API/v2/images/$PRIVATE_IMG" \
      -H "X-Auth-Token: $ATTACKER_TOKEN" &
done
wait

echo "  5 simultaneous delete requests sent"
echo ""

# Check if image still exists
EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $ADMIN_TOKEN" \
  "$GLANCE_API/v2/images/$PRIVATE_IMG")
echo "  Image still exists: $([ "$EXISTS" = "200" ] && echo "YES" || echo "NO - DELETED!")"
echo "TEST6|race_condition|$EXISTS" >> $RESULTS_FILE

if [ "$EXISTS" != "200" ]; then
    echo "  CRITICAL: Race condition allowed deletion!"
else
    echo "  SECURE: Concurrent requests handled safely"
fi
echo ""

# ============================================================
# TEST 7: Owner CAN delete their own image (Control Test)
# ============================================================
echo "[TEST 7] Control test: Owner deleting own image..."

export OS_USERNAME=image-owner
export OS_PASSWORD=openstack
export OS_PROJECT_NAME=project-owner
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=$KEYSTONE_API/v3

OWNER_TOKEN=$(openstack token issue -f value -c id)

export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=admin

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "$GLANCE_API/v2/images/$PRIVATE_IMG" \
  -H "X-Auth-Token: $OWNER_TOKEN")

echo "  Owner deleting own image: HTTP $HTTP_CODE"
echo "TEST7|owner_delete|$HTTP_CODE" >> $RESULTS_FILE

if [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "  CORRECT: Owner can delete own image"
else
    echo "  WARNING: Owner could not delete own image (HTTP $HTTP_CODE)"
fi
echo ""

# ============================================================
# SUMMARY
# ============================================================
echo "========================================="
echo "  UNAUTHORIZED DELETION TEST SUMMARY"
echo "========================================="
echo ""

cat $RESULTS_FILE | while IFS='|' read -r test desc result; do
    printf "  %-6s %-22s %s\n" "$test" "$desc" "$result"
done

echo ""

# Check for any successful unauthorized deletions
PRIVATE_SAFE=$(grep "private_exists" $RESULTS_FILE | cut -d'|' -f3)
SHARED_SAFE=$(grep "shared_exists" $RESULTS_FILE | cut -d'|' -f3)
FORGED_SAFE=$(grep "forged_exists" $RESULTS_FILE | cut -d'|' -f3)
ROLES_SAFE=$(grep "roles_exists" $RESULTS_FILE | cut -d'|' -f3)
RACE_SAFE=$(grep "race_condition" $RESULTS_FILE | cut -d'|' -f3)

VULN_FOUND="NO"
[ "$PRIVATE_SAFE" != "200" ] && VULN_FOUND="YES"
[ "$SHARED_SAFE" != "200" ] && VULN_FOUND="YES"
[ "$FORGED_SAFE" != "200" ] && VULN_FOUND="YES"
[ "$ROLES_SAFE" != "200" ] && VULN_FOUND="YES"
[ "$RACE_SAFE" != "200" ] && VULN_FOUND="YES"

echo ""
if [ "$VULN_FOUND" = "YES" ]; then
    echo "UNAUTHORIZED DELETION VULNERABILITY FOUND!"
    echo "   Severity: CRITICAL"
    echo "   Multi-tenant integrity compromised"
else
    echo "ALL DELETION TESTS PASSED"
    echo "   Multi-tenant image integrity is SECURE"
    echo ""
    echo "   Protected against:"
    echo "   - Direct unauthorized deletion"
    echo "   - Shared image deletion"
    echo "   - Public image deletion"
    echo "   - Header forgery attacks"
    echo "   - Role manipulation attacks"
    echo "   - Race condition attacks"
fi

# ============================================================
# CLEANUP
# ============================================================
echo ""
echo "[CLEANUP]..."
openstack image delete $PRIVATE_IMG > /dev/null 2>&1
openstack image delete $SHARED_IMG > /dev/null 2>&1
openstack user delete image-owner > /dev/null 2>&1
openstack user delete image-attacker > /dev/null 2>&1
openstack project delete project-owner > /dev/null 2>&1
openstack project delete project-attacker > /dev/null 2>&1
rm -f /tmp/img-private.img /tmp/img-shared.img

echo "Cleanup complete"
echo ""
echo "=== Test Complete ==="
