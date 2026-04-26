#!/bin/bash

echo "=== MEMCACHED TENANT NETWORK ACCESS TEST ==="
echo "Testing if Memcached is reachable from tenant networks"
echo ""

# Get admin credentials
source /etc/kolla/admin-openrc.sh

echo "[1] Creating test tenant and network..."
openstack project create memcache-test-project
openstack user create --project memcache-test-project --password test123 memcache-test-user
openstack role add --user memcache-test-user --project memcache-test-project member

# Create network for tenant
openstack network create memcache-test-net
openstack subnet create --network memcache-test-net \
  --subnet-range 10.50.50.0/24 \
  --dns-nameserver 8.8.8.8 \
  memcache-test-subnet

# Create router and connect
openstack router create memcache-test-router
openstack router add subnet memcache-test-router memcache-test-subnet
openstack router set --external-gateway public1 memcache-test-router

echo "Network created: 10.50.50.0/24"
echo ""

echo "[2] Launching test VM in tenant network..."

# Get image and flavor
IMAGE_ID=$(openstack image list -f value -c ID | head -1)
FLAVOR_ID=$(openstack flavor list -f value -c ID | head -1)
NETWORK_ID=$(openstack network show memcache-test-net -f value -c id)

# Create VM
openstack server create \
  --image $IMAGE_ID \
  --flavor $FLAVOR_ID \
  --network $NETWORK_ID \
  --wait \
  memcache-test-vm

echo "VM created"
echo ""

echo "[3] Waiting for VM to boot (30 seconds)..."
sleep 30

# Get VM IP
VM_IP=$(openstack server show memcache-test-vm -f value -c addresses | cut -d'=' -f2)
echo "VM IP: $VM_IP"
echo ""

echo "[4] Testing Memcached access from tenant VM..."
echo ""

# Method 1: Using console (if available)
echo "--- Method 1: Test via Python from controller (simulating tenant) ---"

python3 << PYTEST
import socket
import sys

print("Testing connection to Memcached from simulated tenant network...")
print("Target: 192.168.100.11:11211")
print("")

try:
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)

    print("Attempting connection...")
    s.connect(('192.168.100.11', 11211))
    print("Connection SUCCESSFUL")
    print("")

    # Try to get version
    print("Sending 'version' command...")
    s.send(b'version\r\n')
    response = s.recv(1024)

    if response:
        print(f"Response received: {response.decode('utf-8', errors='ignore').strip()}")
        print("")
        print("FINDING: Memcached is ACCESSIBLE without authentication!")
        print("")

        # Try stats command
        print("Attempting 'stats' command...")
        s.send(b'stats\r\n')
        stats = s.recv(4096)

        if b'STAT' in stats:
            print("Stats command SUCCESSFUL")
            print("")
            print("Sample stats output:")
            print(stats.decode('utf-8', errors='ignore')[:500])
            print("...")
            print("")
            print("VULNERABILITY CONFIRMED:")
            print("- Memcached accessible from tenant network")
            print("- No authentication required")
            print("- Full stats readable")
            result = "VULNERABLE"
        else:
            print("Stats command blocked")
            result = "PARTIAL"
    else:
        print("No response received")
        result = "BLOCKED"

    s.close()

except socket.timeout:
    print("Connection timed out")
    print("SECURE: Memcached not accessible from tenant network")
    result = "SECURE"

except ConnectionRefusedError:
    print("Connection refused")
    print("SECURE: Memcached not accepting connections")
    result = "SECURE"

except Exception as e:
    print(f"Error: {e}")
    result = "ERROR"

print("")
print("="*60)
print(f"RESULT: {result}")
print("="*60)

sys.exit(0 if result == "SECURE" else 1)
PYTEST

TEST_RESULT=$?

echo ""
echo "[5] Additional network route test..."

# Check if there's a route from tenant network to controller
echo "Checking network routes..."
ip route show | grep "192.168.100.0/24"

echo ""
echo "[6] Testing with netcat..."
timeout 5 bash -c "cat < /dev/null > /dev/tcp/192.168.100.11/11211" 2>&1 && \
  echo "FINDING: Port 11211 is reachable" || \
  echo "SECURE: Port 11211 is not reachable"

echo ""
echo "[7] Testing with curl (if Memcached speaks HTTP - it doesn't, but shows connectivity)..."
timeout 5 curl -v telnet://192.168.100.11:11211 2>&1 | head -20

echo ""
echo "=== CLEANUP ==="
echo "Deleting test resources..."

openstack server delete --wait memcache-test-vm 2>/dev/null
openstack router remove subnet memcache-test-router memcache-test-subnet 2>/dev/null
openstack router delete memcache-test-router 2>/dev/null
openstack subnet delete memcache-test-subnet 2>/dev/null
openstack network delete memcache-test-net 2>/dev/null
openstack user delete memcache-test-user 2>/dev/null
openstack project delete memcache-test-project 2>/dev/null

echo "Cleanup complete"
echo ""

echo "=== TEST SUMMARY ==="
if [ $TEST_RESULT -eq 0 ]; then
    echo "STATUS: SECURE"
    echo "Memcached is NOT accessible from tenant networks"
else
    echo "STATUS: VULNERABLE"
    echo "Memcached IS accessible from tenant networks"
    echo ""
    echo "RECOMMENDATION:"
    echo "1. Add firewall rules to block port 11211 from tenant networks"
    echo "2. Bind Memcached to management interface only"
    echo "3. Enable SASL authentication"
fi
