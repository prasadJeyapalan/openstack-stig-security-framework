================================================================================
STIG Control V-009: OSDB-AUTH-001
MariaDB Credential Protection
================================================================================

STIG ID: OSDB-AUTH-001
Severity: CAT I
Rule Title: MariaDB credentials must be protected through network access controls and file permissions

Vulnerability Discussion:

Database credential protection is essential for preventing unauthorized access to OpenStack infrastructure data. The MariaDB root password and service account credentials are stored in /etc/kolla/passwords.yml and used by OpenStack services to access the database.

Two primary attack vectors threaten database credentials:
1. File-based credential extraction via CVE-2024-32498 (OSGL-CVE-001)
2. Network-based brute force or stolen credential use (OSDB-NET-001)

Defense-in-depth requires protection at multiple layers:
- File system: Restrict access to passwords.yml (OSFS-CRED-001)
- Application: Prevent malicious file extraction (OSGL-CVE-001)
- Network: Block unauthorized database connections (OSDB-NET-001)

Even if an attacker successfully extracts database credentials through file access vulnerabilities, network-level access controls prevent them from using those credentials to connect to MariaDB from unauthorized networks.

Attack Chain Without Network Controls:

1. Attacker exploits CVE-2024-32498 to extract /etc/kolla/passwords.yml
2. Obtains database_password in plaintext
3. Connects to MariaDB from tenant VM: mysql -h 192.168.100.11 -u root -p
4. Authenticates using stolen password
5. Gains full database access
6. Extracts all infrastructure data

Attack Chain With Network Controls (Blocked):

1. Attacker exploits CVE-2024-32498 to extract /etc/kolla/passwords.yml
2. Obtains database_password in plaintext
3. Attempts connection: mysql -h 192.168.100.11 -u root -p
4. Connection REFUSED by firewall (port 3306 blocked)
5. Cannot use stolen credentials
6. Attack chain broken

CVSS 3.1 Score: 10.0 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Check Text:

Verify network access controls and file permissions protect database credentials from unauthorized use.

Method 1: Verify Network Protection (Primary Control)
Check that OSDB-NET-001 controls are active:

    sudo iptables -L INPUT -n -v | grep 3306

Expected: Firewall rules blocking port 3306 from unauthorized networks

Test network access is blocked:

    # From external host
    telnet 192.168.100.11 3306

Expected: Connection refused

Method 2: Verify File Permissions (Defense-in-Depth)
Check that OSFS-CRED-001 controls are active:

    ls -la /etc/kolla/passwords.yml

Expected: -rw------- (600 permissions, root owner)

Method 3: Verify Application Controls (Defense-in-Depth)
Check that OSGL-CVE-001 controls are active:

    sudo docker exec glance_api cat /etc/glance/policy.yaml | grep add_image

Expected: "add_image": "role:admin"

Method 4: Comprehensive Verification
Run the MariaDB exposure test:

    bash ~/openstack-security-assessment/appendix-c-test-scripts/test-mariadb-network-exposure.sh

Expected: Connection refused, credentials cannot be used

Fix Text:

This control is implemented through a combination of existing STIG controls that work together to protect database credentials.

Primary Protection - Network Access Control (OSDB-NET-001):

Apply firewall rules to prevent network access to MariaDB:

    bash ~/openstack-security-assessment/remediation/VULN-012/apply-remediation.sh

This blocks unauthorized use of database credentials even if they are obtained.

Supporting Protection - File Permissions (OSFS-CRED-001):

Restrict access to credentials file:

    sudo chmod 600 /etc/kolla/passwords.yml
    sudo chown root:root /etc/kolla/passwords.yml

This prevents unauthorized reading of database credentials.

Supporting Protection - Application Control (OSGL-CVE-001):

Prevent credential extraction via malicious images:

    bash ~/openstack-security-assessment/remediation/VULN-003/apply-remediation.sh

This blocks the primary credential extraction attack vector.

Verification:

Verify defense-in-depth is active:

    # Check network protection
    sudo iptables -L INPUT -n -v | grep 3306
    
    # Check file protection
    ls -la /etc/kolla/passwords.yml
    
    # Check application protection
    sudo docker exec glance_api cat /etc/glance/policy.yaml | grep add_image

Expected: All three layers of protection are active

Defense-in-Depth Architecture:

Layer 1 - Application (OSGL-CVE-001):
- Prevents credential extraction via CVE-2024-32498
- Blocks unauthorized image uploads
- Status: ACTIVE

Layer 2 - File System (OSFS-CRED-001):
- Restricts read access to passwords.yml
- Prevents local credential theft
- Status: ACTIVE

Layer 3 - Network (OSDB-NET-001):
- Blocks remote database connections
- Prevents credential usage from unauthorized networks
- Status: ACTIVE

Result: Even if one layer fails, remaining layers prevent credential compromise

Additional Recommendations:

For production deployments, consider:
- Rotating database passwords regularly
- Using separate credentials for each service (least privilege)
- Implementing database audit logging
- Encrypting passwords.yml with system-level encryption
- Using secrets management tools (Vault, etc.)
- Monitoring failed authentication attempts

CCI: CCI-000213, CCI-001414, CCI-000366

NIST 800-53 Mappings:
- AC-3: Access Enforcement
- AC-6: Least Privilege
- IA-5: Authenticator Management
- IA-5(1): Password-Based Authentication
- SC-7: Boundary Protection
- SC-28: Protection of Information at Rest

CVSS Before: 10.0 (Critical)
CVSS After: 0.0 (Remediated)
Reduction: 10.0 points (100%)

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

Note: Implemented through defense-in-depth combination of OSDB-NET-001, OSFS-CRED-001, and OSGL-CVE-001

================================================================================
