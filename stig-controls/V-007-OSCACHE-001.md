================================================================================
STIG Control V-007: OSCACHE-001
Memcached Network Access Restriction
================================================================================

STIG ID: OSCACHE-001
Severity: CAT I
Rule Title: Memcached must restrict network access to management network only

Vulnerability Discussion:

Memcached network exposure allows tenant VMs and unauthorized network access to the token cache directly, bypassing all authentication controls. Memcached stores Keystone authentication tokens in plaintext, including admin tokens with full infrastructure access.

When Memcached port 11211 is accessible from networks beyond the management network, attackers can:
1. Connect to Memcached remotely without authentication (port 11211)
2. Execute stats commands to enumerate memory slabs
3. Use stats cachedump to list all cached keys
4. Extract token keys (40-character SHA1 hashes)
5. Retrieve complete token data including usernames, roles, projects
6. Identify and extract admin authentication tokens
7. Use stolen tokens directly in OpenStack API calls
8. Impersonate any user including administrators
9. Gain complete infrastructure control without passwords

This represents a complete authentication bypass vulnerability. In testing, 16 memory slabs were discovered containing 20 authentication token keys that could be extracted and used for API access.

Memcached has no built-in authentication mechanism. Security relies entirely on network-level access control. Memcached should only be accessible from the management network (192.168.100.0/24) where OpenStack services run.

Attack Scenario:

1. Attacker gains access to network with connectivity to OpenStack controller
2. Scans for open Memcached port: nmap -p 11211 192.168.100.11
3. Connects to Memcached: telnet 192.168.100.11 11211
4. Retrieves statistics: stats items (discovers 16 slabs)
5. Enumerates keys: stats cachedump 1 100 (finds token keys)
6. Extracts tokens: get <token-key> (retrieves authentication data)
7. Identifies admin tokens by parsing role information
8. Uses stolen token: curl -H "X-Auth-Token: <stolen-token>" http://192.168.100.11:8774/v2.1/servers
9. Executes privileged operations as admin without password
10. Creates backdoor accounts, exfiltrates data, modifies infrastructure

CVSS 3.1 Score: 9.1 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

Check Text:

Verify Memcached is restricted to management network only and token extraction is prevented.

Method 1: Automated Comprehensive Test
Run the comprehensive Memcached network exposure test:

    bash ~/openstack-security-assessment/appendix-c-test-scripts/test-memcached-network-exposure.sh

Expected output (PROTECTED state):
    Vulnerability Status: REMEDIATED [PROTECTED]
    Connection: REFUSED
    Port 11211: BLOCKED

Expected output (VULNERABLE state):
    Vulnerability Status: CONFIRMED [VULNERABLE]
    Slabs discovered: 16
    Token-like keys: 20
    Complete tokens extracted: 5

Method 2: Manual Network Test
Test from external host or tenant VM:

    telnet 192.168.100.11 11211

Expected (PROTECTED): Connection refused or timeout
Expected (VULNERABLE): Connected, can send commands

Method 3: Firewall Rules Check
Verify iptables rules restrict access:

    sudo iptables -L INPUT -n -v --line-numbers | grep 11211

Expected output should show:
    Chain INPUT
    num   pkts bytes target     prot opt in     out     source               destination
    X        0     0 ACCEPT     tcp  --  br-mgmt *     192.168.100.0/24     0.0.0.0/0            tcp dpt:11211
    Y        0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:11211

Where X < Y (ACCEPT rule comes before DROP rule)

Method 4: Verify Persistent Rules
Check saved iptables configuration:

    sudo cat /etc/iptables/rules.v4 | grep 11211

Expected: Rules present in saved configuration

Fix Text:

Step 1: Install iptables-persistent (if not already installed)

    sudo apt-get update
    sudo apt-get install -y iptables-persistent

Step 2: Configure Firewall Rules

Allow Memcached access only from management network:

    sudo iptables -I INPUT -s 192.168.100.0/24 -p tcp --dport 11211 -j ACCEPT

Drop all other access to Memcached:

    sudo iptables -A INPUT -p tcp --dport 11211 -j DROP

Note: Order matters - ACCEPT rule must come before DROP rule

Step 3: Verify Rules Are Active

Check rule order and configuration:

    sudo iptables -L INPUT -n -v --line-numbers | grep 11211

Expected: ACCEPT rule with lower line number than DROP rule

Step 4: Save Firewall Rules

Persist rules across reboots:

    sudo mkdir -p /etc/iptables
    sudo iptables-save > /etc/iptables/rules.v4

Enable persistence service:

    sudo systemctl enable netfilter-persistent
    sudo systemctl start netfilter-persistent

Step 5: Verify Remediation

Test that external access is blocked:

    # From external host or WSL
    telnet 192.168.100.11 11211

Expected: Connection refused

Test that management network can still access:

    # From OpenStack controller
    telnet 192.168.100.11 11211

Expected: Connected (Memcached accessible from management network)

Run comprehensive test script:

    bash ~/openstack-security-assessment/appendix-c-test-scripts/test-memcached-network-exposure.sh

Expected output:
    Vulnerability Status: REMEDIATED [PROTECTED]
    Connection: REFUSED
    Token extraction: BLOCKED

Automated Remediation Script:

For automated application of this control, execute:

    bash ~/openstack-security-assessment/remediation/VULN-011/apply-remediation.sh

Testing Evidence:

Before remediation (VULNERABLE state):
- Network connectivity: CONNECTED
- Slabs discovered: 16
- Token-like keys found: 20
- Complete tokens extracted: 5
- Impact: Complete authentication bypass possible

After remediation (PROTECTED state):
- Network connectivity: REFUSED
- Token extraction: BLOCKED
- Impact: Authentication bypass prevented

Defense-in-Depth:

This control should be combined with:
- Strong token expiration policies
- Token revocation monitoring
- Network segmentation between management and tenant networks
- Intrusion detection monitoring for port 11211 access attempts
- Regular security audits of Memcached configuration

Additional Security Considerations:

While network-level access control provides strong protection, consider:
- Enabling Memcached SASL authentication for additional security
- Using encrypted connections if supported
- Monitoring Memcached logs for unusual access patterns
- Implementing token encryption at rest (future enhancement)

CCI: CCI-000213, CCI-001414, CCI-000366

NIST 800-53 Mappings:
- AC-3: Access Enforcement
- AC-3(7): Access Enforcement - Role-Based Access Control
- SC-7: Boundary Protection
- SC-7(5): Boundary Protection - Deny by Default
- CM-6: Configuration Settings
- CM-7: Least Functionality

CVSS Before: 9.1 (Critical)
CVSS After: 0.0 (Remediated)
Reduction: 9.1 points (100%)

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

Test Results:
- Pre-remediation: 20 authentication tokens extracted
- Post-remediation: Connection refused, token extraction blocked

================================================================================
