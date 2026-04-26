================================================================================
STIG Control V-010: OSFS-CRED-001
Credential File Permissions
================================================================================

STIG ID: OSFS-CRED-001
Severity: CAT I
Rule Title: OpenStack credential files must be readable by root only

Vulnerability Discussion:

The /etc/kolla/passwords.yml file contains plaintext credentials for all OpenStack services including database root password, RabbitMQ credentials, Keystone admin password, and service account credentials. In testing, this file contained 126 distinct credentials for the entire infrastructure.

Default Kolla-Ansible deployment sets file permissions to 644 or 640 (readable by group), which allows unauthorized users to read all infrastructure credentials. This creates multiple attack vectors:

1. Local privilege escalation via credential theft
2. Enables CVE-2024-32498 exploitation (malicious image can extract file)
3. Allows lateral movement within compromised systems
4. Provides credentials for all OpenStack services

An attacker who can read /etc/kolla/passwords.yml gains:
- Database root password (access to all OpenStack databases)
- RabbitMQ credentials (message queue access)
- Keystone admin password (full authentication control)
- Service account credentials (API access as services)
- Memcached keys and secrets
- Encryption keys and tokens

Attack Scenarios:

Scenario 1 - Local Privilege Escalation:
1. Attacker compromises low-privilege account on controller
2. Reads /etc/kolla/passwords.yml (if permissions allow)
3. Extracts database_password
4. Connects to MariaDB as root
5. Creates admin user in keystone database
6. Gains admin access to entire infrastructure

Scenario 2 - CVE-2024-32498 Amplification:
1. Attacker exploits CVE-2024-32498 to extract files
2. Targets /etc/kolla/passwords.yml
3. If permissions allow, extracts 126 credentials
4. Uses database password to access MariaDB
5. Uses admin password for Keystone authentication
6. Achieves complete infrastructure compromise

Scenario 3 - Insider Threat:
1. User with legitimate shell access to controller
2. Reads passwords.yml (if group-readable)
3. Copies credentials for later use
4. Leaves organization but retains credential access
5. Returns later using stolen credentials

CVSS 3.1 Score: 7.8 (High)
CVSS Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Check Text:

Verify /etc/kolla/passwords.yml permissions are 600 and owned by root only.

Method 1: File Permissions Check

    ls -la /etc/kolla/passwords.yml

Expected output:
    -rw------- 1 root root 15234 Jan 30 10:00 /etc/kolla/passwords.yml

Expected permissions: 600 (rw-------)
Expected owner: root
Expected group: root

Method 2: Permission Value Check

    stat -c "%a %U:%G %n" /etc/kolla/passwords.yml

Expected output:
    600 root:root /etc/kolla/passwords.yml

Method 3: Group Access Test
Test that group members cannot read file:

    sudo -u kolla cat /etc/kolla/passwords.yml 2>&1

Expected: Permission denied

Method 4: World Access Test
Verify world-readable bit is not set:

    stat -c "%A" /etc/kolla/passwords.yml | grep -o "^.......r"

Expected: No output (world-read bit not set)

Method 5: Content Verification
Verify file contains credentials:

    sudo wc -l /etc/kolla/passwords.yml

Expected: Approximately 200-300 lines containing credential pairs

Fix Text:

Step 1: Backup Current File (Optional)

    sudo cp /etc/kolla/passwords.yml /etc/kolla/passwords.yml.backup
    sudo chmod 600 /etc/kolla/passwords.yml.backup

Step 2: Restrict File Permissions

Set file to be readable only by root:

    sudo chmod 600 /etc/kolla/passwords.yml

Expected result: -rw-------

Step 3: Set Root Ownership

Ensure file is owned by root:

    sudo chown root:root /etc/kolla/passwords.yml

Step 4: Verify Remediation

Check permissions:

    ls -la /etc/kolla/passwords.yml

Expected:
    -rw------- 1 root root [size] [date] /etc/kolla/passwords.yml

Verify only root can read:

    sudo -u kolla cat /etc/kolla/passwords.yml

Expected: Permission denied

Step 5: Test OpenStack Services Still Function

Verify services can still access credentials:

    sudo docker ps | grep -E "keystone|glance|neutron|nova"

Expected: All services running (containers in "Up" status)

Test basic OpenStack functionality:

    source ~/admin-openrc.sh
    openstack service list

Expected: Service list displayed successfully

Automated Remediation Script:

For automated application of this control, execute:

    bash ~/openstack-security-assessment/remediation/VULN-014/apply-remediation.sh

Defense-in-Depth Integration:

This control works in conjunction with:

Layer 1 - File Permissions (This Control):
- Prevents local users from reading credentials
- Blocks low-privilege account access
- Status: ACTIVE (chmod 600)

Layer 2 - Application Control (OSGL-CVE-001):
- Prevents remote file extraction via malicious images
- Blocks CVE-2024-32498 exploitation
- Status: ACTIVE (image upload restricted)

Layer 3 - Network Control (OSDB-NET-001):
- Prevents use of stolen database credentials
- Blocks remote database connections
- Status: ACTIVE (port 3306 restricted)

Result: Multi-layered protection prevents credential compromise and misuse

Additional Security Considerations:

For production deployments, consider:
- Encrypting passwords.yml at rest using system-level encryption
- Using secrets management systems (HashiCorp Vault, etc.)
- Implementing file integrity monitoring (AIDE, Tripwire)
- Auditing file access attempts
- Rotating credentials regularly
- Limiting shell access to controller nodes
- Implementing least-privilege access models

Monitoring:

Monitor file access attempts:

    sudo auditctl -w /etc/kolla/passwords.yml -p r -k credential_access
    sudo ausearch -k credential_access

This logs all read attempts to the credentials file.

CCI: CCI-002235, CCI-000196, CCI-000366

NIST 800-53 Mappings:
- AC-6: Least Privilege
- AC-6(1): Least Privilege - Authorize Access to Security Functions
- IA-5: Authenticator Management
- IA-5(1): Password-Based Authentication
- CM-6: Configuration Settings
- SC-28: Protection of Information at Rest

CVSS Before: 7.8 (High)
CVSS After: 0.0 (Remediated)
Reduction: 7.8 points (100%)

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

Note: This control is essential for defense-in-depth and works with OSGL-CVE-001 and OSDB-NET-001 to prevent credential compromise through multiple attack vectors.

================================================================================
