================================================================================
STIG Control V-008: OSDB-NET-001
MariaDB Network Access Restriction
================================================================================

STIG ID: OSDB-NET-001
Severity: CAT I
Rule Title: MariaDB must restrict network access to management network and localhost only

Vulnerability Discussion:

MariaDB network exposure allows direct database access from unauthorized networks, bypassing all application-layer security controls. The database contains all OpenStack configuration, credentials, user data, and infrastructure state.

When MariaDB port 3306 is accessible from networks beyond the management network, attackers can:
1. Connect to MariaDB remotely on port 3306
2. Authenticate using credentials extracted from CVE-2024-32498 exploit
3. Enumerate all OpenStack databases (8 databases discovered in testing)
4. Access keystone database to extract user accounts and password hashes
5. Access nova database to retrieve instance configurations
6. Access glance database to view image metadata
7. Access neutron database to map network topology
8. Access cinder, placement, nova_api, nova_cell0 databases
9. Extract sensitive configuration and credential data
10. Modify database records directly to escalate privileges
11. Create backdoor admin accounts
12. Gain complete control of OpenStack deployment

In testing, successful connection to exposed MariaDB resulted in enumeration of 8 databases containing complete infrastructure state. User table extraction revealed password hashes suitable for offline cracking. Project information disclosed all tenant configurations.

This represents the highest severity vulnerability (CVSS 10.0) as it provides direct access to the entire infrastructure database, bypassing all application security controls.

Attack Scenario:

Phase 1 - Credential Acquisition (via CVE-2024-32498):
1. Attacker uploads malicious QCOW2 image to Glance
2. Downloads converted image containing /etc/kolla/passwords.yml
3. Extracts database_password from credentials file
4. Obtains root password for MariaDB

Phase 2 - Database Access (Network Exposure):
5. Scans for MariaDB port: nmap -p 3306 192.168.100.11
6. Connects remotely: mysql -h 192.168.100.11 -u root -p
7. Enumerates databases: SHOW DATABASES;
8. Discovers 8 OpenStack databases

Phase 3 - Data Extraction:
9. Selects keystone database: USE keystone;
10. Lists tables: SHOW TABLES;
11. Extracts user data: SELECT * FROM user;
12. Retrieves password hashes for offline cracking
13. Extracts project information: SELECT * FROM project;
14. Maps tenant relationships and configurations

Phase 4 - Infrastructure Compromise:
15. Creates backdoor admin account in keystone database
16. Modifies quota limits in nova database
17. Exfiltrates sensitive instance and image data
18. Maintains persistent access to infrastructure

CVSS 3.1 Score: 10.0 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Check Text:

Verify MariaDB is restricted to management network and localhost only, preventing unauthorized database access.

Method 1: Automated Comprehensive Test
Run the comprehensive MariaDB network exposure test:

    bash ~/openstack-security-assessment/appendix-c-test-scripts/test-mariadb-network-exposure.sh

Expected output (PROTECTED state):
    Vulnerability Status: REMEDIATED [PROTECTED]
    Connection: REFUSED
    Port 3306: BLOCKED

Expected output (VULNERABLE state):
    Vulnerability Status: CONFIRMED [VULNERABLE]
    Connection: SUCCESSFUL
    Databases enumerated: 8
    User table: Extracted
    Password hashes: Accessible

Method 2: Manual Network Test
Test from external host or tenant VM:

    telnet 192.168.100.11 3306

Expected (PROTECTED): Connection refused or timeout
Expected (VULNERABLE): MySQL protocol response visible

Alternative test with mysql client:

    mysql -h 192.168.100.11 -u root -p

Expected (PROTECTED): Connection refused
Expected (VULNERABLE): Password prompt (connection established)

Method 3: Firewall Rules Check
Verify iptables rules restrict access:

    sudo iptables -L INPUT -n -v --line-numbers | grep 3306

Expected output should show:
    Chain INPUT
    num   pkts bytes target     prot opt in     out     source               destination
    X        0     0 ACCEPT     tcp  --  *      *     192.168.100.0/24     0.0.0.0/0            tcp dpt:3306
    Y        0     0 ACCEPT     tcp  --  lo     *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3306
    Z        0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3306

Where X, Y < Z (ACCEPT rules before DROP rule)

Method 4: Verify Persistent Rules
Check saved iptables configuration:

    sudo cat /etc/iptables/rules.v4 | grep 3306

Expected: Rules present in saved configuration

Fix Text:

Step 1: Install iptables-persistent (if not already installed)

    sudo apt-get update
    sudo apt-get install -y iptables-persistent

Step 2: Configure Firewall Rules

Allow MariaDB access from management network:

    sudo iptables -I INPUT -s 192.168.100.0/24 -p tcp --dport 3306 -j ACCEPT

Allow localhost access (required for OpenStack services):

    sudo iptables -I INPUT -i lo -p tcp --dport 3306 -j ACCEPT

Drop all other access to MariaDB:

    sudo iptables -A INPUT -p tcp --dport 3306 -j DROP

Note: Order is critical - ACCEPT rules must come before DROP rule

Step 3: Verify Rules Are Active

Check rule order and configuration:

    sudo iptables -L INPUT -n -v --line-numbers | grep 3306

Expected: Both ACCEPT rules with lower line numbers than DROP rule

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
    telnet 192.168.100.11 3306

Expected: Connection refused

Test that localhost still works:

    # From OpenStack controller
    mysql -h localhost -u root -p

Expected: Password prompt (connection successful)

Run comprehensive test script:

    bash ~/openstack-security-assessment/appendix-c-test-scripts/test-mariadb-network-exposure.sh

Expected output:
    Vulnerability Status: REMEDIATED [PROTECTED]
    Connection: REFUSED
    Database access: BLOCKED

Automated Remediation Script:

For automated application of this control, execute:

    bash ~/openstack-security-assessment/remediation/VULN-012/apply-remediation.sh

Testing Evidence:

Before remediation (VULNERABLE state):
- Network connectivity: SUCCESSFUL
- Authentication: SUCCESSFUL (using stolen credentials)
- Databases enumerated: 8 (keystone, nova, glance, neutron, cinder, placement, nova_api, nova_cell0)
- User table: Extracted with password fields
- Projects: 9 projects enumerated
- Password hashes: Accessible for offline cracking
- Impact: Complete database compromise

After remediation (PROTECTED state):
- Network connectivity: REFUSED
- Database access: BLOCKED
- Data extraction: PREVENTED
- Impact: Database compromise prevented

Defense-in-Depth:

This control should be combined with:
- OSGL-CVE-001: Prevent credential extraction via CVE-2024-32498
- OSFS-CRED-001: Restrict /etc/kolla/passwords.yml file permissions
- Strong database passwords (rotate after credential exposure)
- Database access logging and monitoring
- Network segmentation between management and tenant networks
- Intrusion detection monitoring for port 3306 access attempts
- Regular database security audits

Additional Security Considerations:

While network-level access control provides strong protection:
- Rotate database passwords if credentials were previously exposed
- Enable MariaDB audit plugin for access logging
- Consider database encryption at rest
- Implement least-privilege database accounts for services
- Monitor failed authentication attempts
- Regular backup and recovery testing

CCI: CCI-000213, CCI-001414, CCI-000366

NIST 800-53 Mappings:
- AC-3: Access Enforcement
- AC-3(7): Access Enforcement - Role-Based Access Control
- AC-6: Least Privilege
- SC-7: Boundary Protection
- SC-7(5): Boundary Protection - Deny by Default
- CM-6: Configuration Settings
- CM-7: Least Functionality

CVSS Before: 10.0 (Critical)
CVSS After: 0.0 (Remediated)
Reduction: 10.0 points (100%)

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

Test Results:
- Pre-remediation: 8 databases enumerated, user data extracted, password hashes accessible
- Post-remediation: Connection refused, database access blocked

================================================================================
