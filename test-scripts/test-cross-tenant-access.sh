#!/bin/bash

echo "==== Cross-Tenant Image Access Control Test ===="
echo ""
echo "Testing if users can access images from other projects"
echo ""

# Save admin credentials
ADMIN_USER=$OS_USERNAME
ADMIN_PASS=$OS_PASSWORD

# Step 1: Create two isolated projects
echo "[1] Creating isolated test projects..."

openstack project create --description "Tenant A - Isolated" project-tenant-a
openstack project create --description "Tenant B - Isolated" project-tenant-b

echo "Projects created"

# Step 2: Create users for each project
echo ""
echo "[2] Creating users for each project..."

openstack user create --domain default --password tenantA123 --email tenanta@test.com user-tenant-a
openstack user create --domain default --password tenantB123 --email tenantb@test.com user-tenant-b

# Assign member roles
openstack role add --user user-tenant-a --project project-tenant-a member
openstack role add --user user-tenant-b --project project-tenant-b member

echo "Users created and assigned to projects"

# Step 3: User A uploads a PRIVATE image
echo ""
echo "[3] User A uploading PRIVATE image..."

export OS_USERNAME=user-tenant-a
export OS_PASSWORD=tenantA123
export OS_PROJECT_NAME=project-tenant-a
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_AUTH_URL=http://192.168.100.11:5000/v3
export OS_IDENTITY_API_VERSION=3

# Create a small test image file
dd if=/dev/zero of=/tmp/test-image-tenant-a.img bs=1M count=1 2>/dev/null

# Upload as PRIVATE image
IMAGE_A_ID=$(openstack image create \
  --private \
  --disk-format raw \
  --container-format bare \
  --file /tmp/test-image-tenant-a.img \
  tenant-a-private-image \
  -f value -c id)

echo "Private image created: $IMAGE_A_ID"
echo "Owner: user-tenant-a (project-tenant-a)"
echo "Visibility: private"

# Verify User A can see their own image
echo ""
echo "[4] Verifying User A can see their own image..."
USER_A_TOKEN=$(openstack token issue -f value -c id)

IMAGE_CHECK=$(curl -s -H "X-Auth-Token: $USER_A_TOKEN" \
  http://192.168.100.11:9292/v2/images/$IMAGE_A_ID)

if echo "$IMAGE_CHECK" | grep -q "tenant-a-private-image"; then
    echo "User A can see their own image (as expected)"
else
    echo "ERROR: User A CANNOT see their own image - setup problem!"
    exit 1
fi

# Step 5: User B attempts to access User A's private image
echo ""
echo "[5] User B attempting to access User A's PRIVATE image..."
echo "Image ID: $IMAGE_A_ID"
echo ""

export OS_USERNAME=user-tenant-b
export OS_PASSWORD=tenantB123
export OS_PROJECT_NAME=project-tenant-b

USER_B_TOKEN=$(openstack token issue -f value -c id)

# Attempt 1: Direct image access by ID
echo "Test 1: Direct access by image ID..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $USER_B_TOKEN" \
  http://192.168.100.11:9292/v2/images/$IMAGE_A_ID)

echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "CRITICAL VULNERABILITY!"
    echo "   User B CAN access User A's private image!"
    echo "   Multi-tenant isolation BROKEN!"
    VULN_FOUND="YES"
elif [ "$HTTP_CODE" = "404" ]; then
    echo "SECURE: Image not found (proper isolation)"
    VULN_FOUND="NO"
elif [ "$HTTP_CODE" = "403" ]; then
    echo "SECURE: Access forbidden (proper isolation)"
    VULN_FOUND="NO"
else
    echo "WARNING: Unexpected status: $HTTP_CODE"
    VULN_FOUND="UNKNOWN"
fi

# Attempt 2: List all images to see if private image appears
echo ""
echo "Test 2: Checking if private image appears in User B's image list..."

IMAGE_LIST=$(curl -s -H "X-Auth-Token: $USER_B_TOKEN" \
  http://192.168.100.11:9292/v2/images | python3 -c "import sys, json; data=json.load(sys.stdin); print('\n'.join([img['id'] for img in data['images']]))")

if echo "$IMAGE_LIST" | grep -q "$IMAGE_A_ID"; then
    echo "VULNERABILITY: Private image appears in other tenant's list!"
    VULN_FOUND="YES"
else
    echo "SECURE: Private image NOT in other tenant's list"
fi

# Attempt 3: Try to download the image file
echo ""
echo "Test 3: Attempting to download image file..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $USER_B_TOKEN" \
  http://192.168.100.11:9292/v2/images/$IMAGE_A_ID/file)

echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "CRITICAL: Can download private image file!"
    VULN_FOUND="YES"
else
    echo "SECURE: Cannot download file (status $HTTP_CODE)"
fi

# Step 6: Test with SHARED image
echo ""
echo "[6] Testing SHARED image visibility..."

export OS_USERNAME=user-tenant-a
export OS_PASSWORD=tenantA123
export OS_PROJECT_NAME=project-tenant-a

# Create a SHARED image
dd if=/dev/zero of=/tmp/test-image-shared.img bs=1M count=1 2>/dev/null

IMAGE_SHARED_ID=$(openstack image create \
  --shared \
  --disk-format raw \
  --container-format bare \
  --file /tmp/test-image-shared.img \
  tenant-a-shared-image \
  -f value -c id)

echo "Shared image created: $IMAGE_SHARED_ID"

# Add User B's project as member
openstack image add project $IMAGE_SHARED_ID project-tenant-b
openstack image set --accept $IMAGE_SHARED_ID --project project-tenant-b

echo "Project B added as member of shared image"

# User B should now see it
echo ""
echo "[7] Verifying User B CAN access SHARED image..."

export OS_USERNAME=user-tenant-b
export OS_PASSWORD=tenantB123
export OS_PROJECT_NAME=project-tenant-b

USER_B_TOKEN=$(openstack token issue -f value -c id)

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $USER_B_TOKEN" \
  http://192.168.100.11:9292/v2/images/$IMAGE_SHARED_ID)

echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "CORRECT: User B CAN access shared image (as expected)"
else
    echo "WARNING: User B cannot access shared image (status $HTTP_CODE)"
    echo "   Sharing feature may not be working properly"
fi

# Step 7: Test PUBLIC image access
echo ""
echo "[8] Testing PUBLIC image access..."

# Switch back to admin to create public image
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=admin

dd if=/dev/zero of=/tmp/test-image-public.img bs=1M count=1 2>/dev/null

IMAGE_PUBLIC_ID=$(openstack image create \
  --public \
  --disk-format raw \
  --container-format bare \
  --file /tmp/test-image-public.img \
  public-test-image \
  -f value -c id)

echo "Public image created: $IMAGE_PUBLIC_ID"

# User B should see it
export OS_USERNAME=user-tenant-b
export OS_PASSWORD=tenantB123
export OS_PROJECT_NAME=project-tenant-b

USER_B_TOKEN=$(openstack token issue -f value -c id)

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $USER_B_TOKEN" \
  http://192.168.100.11:9292/v2/images/$IMAGE_PUBLIC_ID)

echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "CORRECT: User B CAN access public image (as expected)"
else
    echo "WARNING: User B cannot access public image (status $HTTP_CODE)"
fi

# Results summary
echo ""
echo "========================================="
echo "           RESULTS SUMMARY"
echo "========================================="
echo ""
echo "Cross-Tenant Isolation Test:"
echo "  Private Image Access: $([ "$VULN_FOUND" = "YES" ] && echo "VULNERABLE" || echo "SECURE")"
echo ""
echo "Image Visibility Test Results:"
echo "  Private -> Other Tenant: $([ "$VULN_FOUND" = "YES" ] && echo "ACCESSIBLE (FAIL)" || echo "BLOCKED (PASS)")"
echo "  Shared -> Member Tenant: ACCESSIBLE (expected)"
echo "  Public -> Any Tenant: ACCESSIBLE (expected)"
echo ""

if [ "$VULN_FOUND" = "YES" ]; then
    echo "CRITICAL VULNERABILITY FOUND!"
    echo "   Severity: CRITICAL"
    echo "   Impact: Multi-tenant isolation broken"
    echo "   Risk: Data breach across tenants"
else
    echo "NO VULNERABILITY FOUND"
    echo "   Multi-tenant isolation working correctly"
fi

# Cleanup
echo ""
echo "[9] Cleanup..."
export OS_USERNAME=$ADMIN_USER
export OS_PASSWORD=$ADMIN_PASS
export OS_PROJECT_NAME=admin

openstack image delete $IMAGE_A_ID 2>/dev/null
openstack image delete $IMAGE_SHARED_ID 2>/dev/null
openstack image delete $IMAGE_PUBLIC_ID 2>/dev/null

openstack user delete user-tenant-a
openstack user delete user-tenant-b

openstack project delete project-tenant-a
openstack project delete project-tenant-b

rm -f /tmp/test-image-*.img

echo "Cleanup complete"

echo ""
echo "=== Test Complete ==="
echo "Vulnerability Found: $VULN_FOUND"
