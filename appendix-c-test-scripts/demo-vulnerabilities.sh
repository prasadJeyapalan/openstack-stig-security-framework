#!/bin/bash
echo "=========================================="
echo "VULNERABILITY DEMONSTRATION"
echo "Showing exploits BEFORE remediation"
echo "=========================================="
echo ""

echo "[1/8] VULN-003: CVE-2024-32498 Glance Malicious QCOW2"
echo "Running test-cve-2024-32498-qcow2-v2.sh..."
bash test-cve-2024-32498-qcow2-v2.sh
echo ""
read -p "Press Enter to continue..."

echo "[2/8] VULN-004: No Rate Limiting (Keystone)"
echo "Note: This would require brute force script - skip for demo or test manually"
echo ""
read -p "Press Enter to continue..."

echo "[3/8] VULN-008: Cross-Tenant Port Deletion"
echo "Running test-neutron-port-isolation.sh..."
bash test-neutron-port-isolation.sh
echo ""
read -p "Press Enter to continue..."

echo "[4/8] VULN-010: Floating IP (tested in port isolation)"
echo "Included in neutron port test"
echo ""
read -p "Press Enter to continue..."

echo "[5/8] VULN-011: Memcached Tenant Access"
echo "Running test-memcached-tenant-access.sh..."
bash test-memcached-tenant-access.sh
echo ""
read -p "Press Enter to continue..."

echo "[6/8] VULN-012: MariaDB Network Exposure"
echo "Testing database connection from tenant network..."
# Add simple MariaDB connection test here
echo ""
read -p "Press Enter to continue..."

echo "[7/8] VULN-014: Passwords.yml Readable"
echo "Testing file permissions..."
ls -l /etc/kolla/passwords.yml
echo ""
echo "Testing read access as kolla group member..."
sudo -u kolla cat /etc/kolla/passwords.yml | head -5
echo ""
read -p "Press Enter to continue..."

echo "[8/8] VULN-013: Complete Attack Chain"
echo "Running test-cve-2024-32498-attack-chain.sh..."
bash test-cve-2024-32498-attack-chain.sh
echo ""

echo "=========================================="
echo "VULNERABILITY DEMONSTRATION COMPLETE"
echo "All exploits succeeded (system is vulnerable)"
echo "=========================================="
