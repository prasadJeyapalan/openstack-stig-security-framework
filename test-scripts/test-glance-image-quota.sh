#!/bin/bash

# =============================================================
# Glance Image Storage Quota Test
# OpenStack Security Assessment - Practicum
# Assessor: Prasad Jeyapalan
# Date: February 16, 2026
#
# Description:
#   Tests whether Glance enforces per-user image storage quotas.
#   An unconfigured quota (default=0) allows unlimited storage,
#   enabling storage exhaustion / denial of service by any tenant.
#
# Usage: ./test-glance-image-quota.sh
# =============================================================

GLANCE_API="http://192.168.100.11:9292"
IMAGE_SIZE_MB=50
IMAGE_COUNT=5
RESULTS_FILE="/tmp/glance-quota-results.txt"
> $RESULTS_FILE

echo "============================================================"
echo " GLANCE IMAGE QUOTA TEST"
echo " OpenStack Security Assessment"
echo " Date: $(date)"
echo "============================================================"
echo ""

# ============================================================
# STEP 1: Check quota configuration
# ============================================================
echo "=== STEP 1: Check Glance quota configuration ==="
echo ""

QUOTA_CONFIG=$(docker exec glance_api grep -i \
    "user_storage_quota" \
    /etc/glance/glance-api.conf 2>/dev/null)

if [ -n "$QUOTA_CONFIG" ]; then
    echo "  Quota config found: $QUOTA_CONFIG"
    QUOTA_VALUE=$(echo "$QUOTA_CONFIG" | awk -F'=' '{print $2}' | tr -d ' ')
    if [ "$QUOTA_VALUE" = "0" ]; then
        echo "  WARNING: user_storage_quota = 0 (UNLIMITED)"
        QUOTA_STATUS="UNLIMITED"
    else
        echo "  Quota set: $QUOTA_VALUE bytes"
        QUOTA_STATUS="LIMITED"
    fi
else
    echo "  ALERT: user_storage_quota NOT SET"
    echo "  Default value = 0 = UNLIMITED storage per user"
    QUOTA_STATUS="NOT_SET"
fi

echo "STEP1|quota_status|$QUOTA_STATUS" >> $RESULTS_FILE
echo ""

echo "--- OpenStack project quota (Cinder/Nova) ---"
source ~/attacker-openrc.sh
openstack quota show 2>/dev/null | grep -i "gigabyte\|image" | sed 's/^/  /'
echo ""

# ============================================================
# STEP 2: Check current tenant image usage
# ============================================================
echo "=== STEP 2: Current tenant image usage ==="
echo ""

source ~/attacker-openrc.sh
USER_ID=$(openstack token issue -f value -c user_id)
PROJECT_ID=$(openstack token issue -f value -c project_id)

echo "  Actor:      net-attacker"
echo "  User ID:    $USER_ID"
echo "  Project ID: $PROJECT_ID"
echo ""

EXISTING_COUNT=$(openstack image list -f value -c ID | wc -l)
echo "  Existing images visible: $EXISTING_COUNT"
echo "STEP2|existing_images|$EXISTING_COUNT" >> $RESULTS_FILE
echo ""

# ============================================================
# STEP 3: Create test image file
# ============================================================
echo "=== STEP 3: Create ${IMAGE_SIZE_MB}MB test image ==="
echo ""

dd if=/dev/urandom \
    of=/tmp/quota-test.img \
    bs=1M count=$IMAGE_SIZE_MB 2>/dev/null

if [ -f /tmp/quota-test.img ]; then
    echo "  Test image created"
    echo "  Size: $(ls -lh /tmp/quota-test.img | awk '{print $5}')"
else
    echo "  ERROR: Failed to create test image"
    exit 1
fi
echo ""

# ============================================================
# STEP 4: Upload multiple images - test quota enforcement
# ============================================================
echo "=== STEP 4: Upload $IMAGE_COUNT images (${IMAGE_SIZE_MB}MB each) ==="
echo "  Total attempted: $((IMAGE_SIZE_MB * IMAGE_COUNT))MB"
echo ""

TOTAL_UPLOADED=0
BLOCKED_AT=0
UPLOADED_IDS=()

for i in $(seq 1 $IMAGE_COUNT); do
    IMG_ID=$(openstack image create \
        --private \
        --disk-format raw \
        --container-format bare \
        --file /tmp/quota-test.img \
        "quota-test-$i-$(date +%s)" \
        -f value -c id 2>/dev/null)

    if [ -n "$IMG_ID" ]; then
        TOTAL_UPLOADED=$((TOTAL_UPLOADED + IMAGE_SIZE_MB))
        UPLOADED_IDS+=("$IMG_ID")
        echo "  quota-test-$i uploaded ($IMG_ID)"
        echo "     Running total: ${TOTAL_UPLOADED}MB"
        echo "STEP4|upload_$i|SUCCESS|$IMG_ID" >> $RESULTS_FILE
    else
        BLOCKED_AT=$i
        echo "  quota-test-$i BLOCKED - quota enforced at ${TOTAL_UPLOADED}MB"
        echo "STEP4|upload_$i|BLOCKED" >> $RESULTS_FILE
        break
    fi
done

echo ""

# ============================================================
# STEP 5: Verify uploads visible in Glance
# ============================================================
echo "=== STEP 5: Verify uploads in Glance ==="
echo ""

echo "  Images visible to attacker:"
openstack image list --format table | sed 's/^/  /'
echo ""

FINAL_COUNT=$(openstack image list -f value -c ID | wc -l)
NEW_IMAGES=$((FINAL_COUNT - EXISTING_COUNT))
echo "  New images uploaded: $NEW_IMAGES"
echo "  Total storage used:  ${TOTAL_UPLOADED}MB"
echo "STEP5|new_images|$NEW_IMAGES" >> $RESULTS_FILE
echo "STEP5|total_mb|$TOTAL_UPLOADED" >> $RESULTS_FILE
echo ""

# ============================================================
# STEP 6: Admin visibility check
# ============================================================
echo "=== STEP 6: Admin visibility of storage abuse ==="
echo ""

source /etc/kolla/admin-openrc.sh
echo "  Quota-test images visible to admin:"
openstack image list --all -f value -c ID -c Name -c Size | \
    grep "quota-test" | \
    awk '{printf "  %-45s %-30s %s\n", $1, $2, $3}'
echo ""

# Check if any alerting/monitoring exists
echo "  Checking for usage monitoring config..."
USAGE_MONITOR=$(docker exec glance_api grep -i \
    "notify\|monitor\|alert" \
    /etc/glance/glance-api.conf 2>/dev/null | head -3)
if [ -n "$USAGE_MONITOR" ]; then
    echo "  $USAGE_MONITOR"
else
    echo "  WARNING: No usage monitoring configured"
fi
echo ""

# ============================================================
# STEP 7: DoS simulation note
# ============================================================
echo "=== STEP 7: Storage DoS potential ==="
echo ""
echo "  If this loop ran unchecked:"
echo ""
echo "  while true; do"
echo "    openstack image create --disk-format raw \\"
echo "      --file /dev/urandom \"fill-\$(date +%s)\""
echo "  done"
echo ""
echo "  Result: No quota = storage backend exhaustion"
echo "  Impact: Other tenants cannot upload images or create VMs"
echo "  Effect: Platform-wide denial of service"
echo "  NOTE: Loop NOT executed - documented for evidence only"
echo ""

# ============================================================
# RESULTS SUMMARY
# ============================================================
echo "============================================================"
echo " GLANCE IMAGE QUOTA TEST - RESULTS"
echo "============================================================"
echo ""

if [ "$QUOTA_STATUS" = "NOT_SET" ] || [ "$QUOTA_STATUS" = "UNLIMITED" ]; then
    echo "  FINDING CONFIRMED: No image quota enforcement"
    echo ""
    echo "  Quota config:     NOT SET (default = unlimited)"
    echo "  Images uploaded:  $NEW_IMAGES without restriction"
    echo "  Storage consumed: ${TOTAL_UPLOADED}MB with no limit"
    echo "  Blocked at:       NEVER"
    echo ""
    echo "  Risk: Any tenant can exhaust shared storage"
    echo "  CVSS: 5.3 (MEDIUM)"
    echo "  STIG: OSGL-QUOTA-001 (CAT II)"
    echo ""
    echo "  Remediation:"
    echo "  Add to /etc/glance/glance-api.conf:"
    echo "    [DEFAULT]"
    echo "    user_storage_quota = 10737418240  # 10GB"
    RESULT="VULNERABLE"
else
    echo "  Quota enforcement ACTIVE"
    echo "  Blocked at: ${BLOCKED_AT} images / ${TOTAL_UPLOADED}MB"
    RESULT="SECURE"
fi

echo ""
echo "  Results file: $RESULTS_FILE"
echo "SUMMARY|result|$RESULT" >> $RESULTS_FILE
echo "SUMMARY|images_uploaded|$NEW_IMAGES" >> $RESULTS_FILE
echo "SUMMARY|mb_uploaded|$TOTAL_UPLOADED" >> $RESULTS_FILE

# ============================================================
# CLEANUP
# ============================================================
echo ""
echo "=== CLEANUP ==="
source ~/attacker-openrc.sh

for IMG_ID in "${UPLOADED_IDS[@]}"; do
    openstack image delete "$IMG_ID" 2>/dev/null && \
        echo "  Deleted $IMG_ID" || \
        echo "  Could not delete $IMG_ID"
done

rm -f /tmp/quota-test.img
echo "  Temp files removed"
echo ""
echo "=== TEST COMPLETE ==="
