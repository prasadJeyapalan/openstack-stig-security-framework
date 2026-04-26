#!/bin/bash
echo "Cleaning up Memcached vulnerability test resources..."
source /etc/kolla/admin-openrc.sh

# Delete namespace
sudo ip netns delete tenant-test 2>/dev/null
sudo ip link delete veth-host 2>/dev/null

# Delete OpenStack resources
openstack server delete vuln-test-vm 2>/dev/null
sleep 5

openstack router remove subnet vuln-test-router vuln-test-subnet 2>/dev/null
openstack router delete vuln-test-router 2>/dev/null
openstack subnet delete vuln-test-subnet 2>/dev/null
openstack network delete vuln-test-net 2>/dev/null
openstack user delete vuln-test-user 2>/dev/null
openstack project delete memcache-vuln-test 2>/dev/null
openstack flavor delete m1.test 2>/dev/null

echo "Cleanup complete"
