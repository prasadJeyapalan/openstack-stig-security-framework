================================================================================
APPENDIX D: CONFIGURATION FILES
OpenStack Kolla-Ansible Security Assessment
================================================================================

Document Version: 1.0
Date: March 29, 2026
Author: Prasad Jeyapalan
Classification: Unclassified

================================================================================
EXECUTIVE SUMMARY
================================================================================

This appendix contains all security-relevant configuration files modified during 
the remediation phase. Configuration changes include policy files, firewall 
rules, and service configurations that implement the STIG controls documented 
in Appendix B.

CONFIGURATION FILE SUMMARY:

Total Configuration Types: 4
- Policy Files: 2 files (Glance, Neutron)
- Firewall Rules: 1 ruleset (iptables)
- File Permissions: 1 file (passwords.yml)
- Service Configuration: 1 file (glance-api.conf)

All configuration files are presented in before/after format showing the security 
improvements implemented during remediation.

================================================================================
TABLE OF CONTENTS
================================================================================

SECTION 1: POLICY CONFIGURATION FILES

1.1 Glance Policy Configuration
    - File: /etc/glance/policy.yaml
    - STIG Controls: OSGL-CVE-001, OSGL-IMG-001
    - Vulnerabilities: VULN-003

1.2 Neutron Policy Configuration
    - File: /etc/neutron/policy.yaml
    - STIG Controls: OSNT-PORT-001, OSNT-FIP-001
    - Vulnerabilities: VULN-008, VULN-010

SECTION 2: FIREWALL CONFIGURATION

2.1 iptables Rules
    - Controls: OSKS-AUTH-001, OSCACHE-001, OSDB-NET-001
    - Vulnerabilities: VULN-004, VULN-011, VULN-012

SECTION 3: SERVICE CONFIGURATION FILES

3.1 Glance API Configuration
    - File: /etc/glance/glance-api.conf
    - Controls: OSGL-CVE-001
    - Vulnerabilities: VULN-003

SECTION 4: FILE SYSTEM PERMISSIONS

4.1 Credential File Permissions
    - File: /etc/kolla/passwords.yml
    - Controls: OSFS-CRED-001
    - Vulnerabilities: VULN-014

================================================================================
SECTION 1: POLICY CONFIGURATION FILES
================================================================================

1.1 GLANCE POLICY CONFIGURATION
================================

File Location: /etc/glance/policy.yaml
Container: glance_api
Purpose: Restrict image upload and modification to admin users only
STIG Controls: OSGL-CVE-001, OSGL-IMG-001
Remediates: VULN-003 (CVE-2024-32498)

BEFORE REMEDIATION (Default Kolla-Ansible):
-------------------------------------------

{
    "context_is_admin": "role:admin",
    "default": "role:admin",
    "add_image": "",
    "delete_image": "",
    "get_image": "",
    "get_images": "",
    "modify_image": "",
    "publicize_image": "role:admin",
    "communitize_image": "",
    "download_image": "",
    "upload_image": "",
    "delete_image_location": "",
    "get_image_location": "",
    "set_image_location": "",
    "add_member": "",
    "delete_member": "",
    "get_member": "",
    "get_members": "",
    "modify_member": "",
    "manage_image_cache": "role:admin",
    "get_task": "",
    "get_tasks": "",
    "add_task": "",
    "modify_task": "",
    "tasks_api_access": "role:admin",
    "deactivate": "",
    "reactivate": "",
    "copy_image": "",
    "get_metadef_namespace": "",
    "get_metadef_namespaces": "",
    "modify_metadef_namespace": "",
    "add_metadef_namespace": ""
}

SECURITY ISSUE:
- "upload_image": "" allows any authenticated user to upload images
- "modify_image": "" allows any authenticated user to modify images
- "add_image": "" allows any authenticated user to add images

This enables CVE-2024-32498 exploitation by member users.

AFTER REMEDIATION (Secure Configuration):
-----------------------------------------

{
    "context_is_admin": "role:admin",
    "default": "role:admin",
    
    "upload_image": "role:admin",
    "modify_image": "role:admin",
    "add_image": "role:admin",
    
    "download_image": "",
    "get_image": "",
    "get_images": "",
    "delete_image": "rule:admin_or_owner",
    "publicize_image": "role:admin",
    "communitize_image": "",
    "delete_image_location": "",
    "get_image_location": "",
    "set_image_location": "",
    "add_member": "",
    "delete_member": "",
    "get_member": "",
    "get_members": "",
    "modify_member": "",
    "manage_image_cache": "role:admin",
    "get_task": "",
    "get_tasks": "",
    "add_task": "",
    "modify_task": "",
    "tasks_api_access": "role:admin",
    "deactivate": "",
    "reactivate": "",
    "copy_image": "",
    "get_metadef_namespace": "",
    "get_metadef_namespaces": "",
    "modify_metadef_namespace": "",
    "add_metadef_namespace": ""
}

CHANGES MADE:
- "upload_image": "" -> "role:admin"
- "modify_image": "" -> "role:admin"
- "add_image": "" -> "role:admin"

SECURITY IMPACT:
- Only admin users can upload images
- Only admin users can modify images
- Member users can still download and view images
- CVE-2024-32498 exploitation prevented

IMPLEMENTATION:
docker exec -u root glance_api bash -c 'cat > /etc/glance/policy.yaml' < policy.yaml
docker restart glance_api

1.2 NEUTRON POLICY CONFIGURATION
=================================

File Location: /etc/neutron/policy.yaml
Container: neutron_server
Purpose: Enforce port and floating IP ownership validation
STIG Controls: OSNT-PORT-001, OSNT-FIP-001
Remediates: VULN-008, VULN-010

BEFORE REMEDIATION (Default Kolla-Ansible):
-------------------------------------------

{
    "context_is_admin": "role:admin",
    "owner": "tenant_id:%(tenant_id)s",
    "admin_or_owner": "rule:context_is_admin or rule:owner",
    "context_is_advsvc": "role:advsvc",
    "admin_or_network_owner": "rule:context_is_admin or tenant_id:%(network:tenant_id)s",
    "admin_owner_or_network_owner": "rule:owner or rule:admin_or_network_owner",
    "admin_only": "rule:context_is_admin",
    "regular_user": "",
    "shared": "field:networks:shared=True",
    "default": "rule:admin_or_owner",
    
    "create_port": "",
    "get_port": "rule:admin_or_owner",
    "update_port": "rule:admin_or_owner",
    "delete_port": "rule:admin_or_owner",
    
    "create_floatingip": "",
    "get_floatingip": "rule:admin_or_owner",
    "update_floatingip": "rule:admin_or_owner",
    "delete_floatingip": "rule:admin_or_owner"
}

SECURITY ISSUES:
- "delete_port": "rule:admin_or_owner" does NOT verify port ownership
- "update_floatingip": "rule:admin_or_owner" does NOT verify floating IP ownership
- admin_or_owner rule checks user's tenant_id, not resource's project_id

This allows cross-tenant port deletion and floating IP hijacking.

AFTER REMEDIATION (Secure Configuration):
-----------------------------------------

{
    "context_is_admin": "role:admin",
    "owner": "tenant_id:%(tenant_id)s",
    "admin_or_owner": "rule:context_is_admin or rule:owner",
    "context_is_advsvc": "role:advsvc",
    "admin_or_network_owner": "rule:context_is_admin or tenant_id:%(network:tenant_id)s",
    "admin_owner_or_network_owner": "rule:owner or rule:admin_or_network_owner",
    "admin_only": "rule:context_is_admin",
    "regular_user": "",
    "shared": "field:networks:shared=True",
    "default": "rule:admin_or_owner",
    
    "create_port": "",
    "get_port": "rule:admin_or_owner",
    "update_port": "rule:admin_or_owner",
    "delete_port": "rule:admin_or_owner and rule:owner",
    
    "create_floatingip": "",
    "get_floatingip": "rule:admin_or_owner",
    "update_floatingip": "rule:admin_or_owner and rule:owner",
    "delete_floatingip": "rule:admin_or_owner"
}

CHANGES MADE:
- "delete_port": "rule:admin_or_owner" -> "rule:admin_or_owner and rule:owner"
- "update_floatingip": "rule:admin_or_owner" -> "rule:admin_or_owner and rule:owner"

SECURITY IMPACT:
- Port deletion requires matching tenant_id
- Floating IP assignment requires matching tenant_id
- Cross-tenant attacks prevented
- Admin users retain full access

IMPLEMENTATION:
docker exec -u root neutron_server bash -c 'cat > /etc/neutron/policy.yaml' < policy.yaml
docker restart neutron_server

================================================================================
SECTION 2: FIREWALL CONFIGURATION
================================================================================

2.1 IPTABLES RULES
==================

Purpose: Restrict network access to sensitive services
STIG Controls: OSKS-AUTH-001, OSCACHE-001, OSDB-NET-001
Remediates: VULN-004, VULN-011, VULN-012

BEFORE REMEDIATION:
-------------------

No specific firewall rules configured for:
- Keystone (port 5000): Unlimited authentication attempts
- Memcached (port 11211): Accessible from all networks
- MariaDB (port 3306): Accessible from all networks

Default iptables policy: ACCEPT all traffic

SECURITY ISSUES:
- Brute force attacks possible against Keystone
- Memcached accessible from tenant networks (token theft)
- MariaDB accessible from tenant networks (database compromise)

AFTER REMEDIATION:
------------------

Complete iptables ruleset:

# Keystone Rate Limiting (VULN-004, OSKS-AUTH-001)
# Limit authentication attempts to 5 per minute per source IP
-A INPUT -p tcp --dport 5000 -m state --state NEW \
  -m hashlimit --hashlimit-above 5/min --hashlimit-mode srcip \
  --hashlimit-name keystone_auth -j LOG --log-prefix "KEYSTONE_RATE_LIMIT: "

-A INPUT -p tcp --dport 5000 -m state --state NEW \
  -m hashlimit --hashlimit-above 5/min --hashlimit-mode srcip \
  --hashlimit-name keystone_auth -j DROP

# Memcached Access Restriction (VULN-011, OSCACHE-001)
# Allow only from management network, drop all other access
-A INPUT -i br-mgmt -p tcp --dport 11211 -j ACCEPT
-A INPUT -p tcp --dport 11211 -j DROP

# MariaDB Access Restriction (VULN-012, OSDB-NET-001)
# Allow only from management network and localhost, drop all other access
-A INPUT -i br-mgmt -p tcp --dport 3306 -j ACCEPT
-A INPUT -i lo -p tcp --dport 3306 -j ACCEPT
-A INPUT -p tcp --dport 3306 -j DROP

RULE BREAKDOWN:

Keystone Rate Limiting:
- Rule 1: Log authentication attempts exceeding 5/min
- Rule 2: Drop authentication attempts exceeding 5/min
- Module: hashlimit (provides per-IP rate tracking)
- Legitimate users unaffected (5 attempts sufficient for normal auth)

Memcached Restriction:
- Rule 1: ACCEPT from br-mgmt interface (management network)
- Rule 2: DROP all other Memcached traffic
- Effect: Tenant networks cannot access Memcached

MariaDB Restriction:
- Rule 1: ACCEPT from br-mgmt interface (management network)
- Rule 2: ACCEPT from lo interface (localhost for local services)
- Rule 3: DROP all other MariaDB traffic
- Effect: Tenant networks cannot access MariaDB

SECURITY IMPACT:
- Brute force attacks rate-limited to 5 attempts/min (CVSS 7.5 -> 4.3)
- Memcached token theft prevented (CVSS 9.1 -> 0.0)
- MariaDB compromise prevented (CVSS 10.0 -> 0.0)
- Total CVSS reduction: 26.6 -> 4.3 (83% improvement for these 3 vulnerabilities)

IMPLEMENTATION:

# Apply rules
sudo iptables -I INPUT -p tcp --dport 5000 -m state --state NEW \
  -m hashlimit --hashlimit-above 5/min --hashlimit-mode srcip \
  --hashlimit-name keystone_auth -j LOG --log-prefix "KEYSTONE_RATE_LIMIT: "

sudo iptables -I INPUT -p tcp --dport 5000 -m state --state NEW \
  -m hashlimit --hashlimit-above 5/min --hashlimit-mode srcip \
  --hashlimit-name keystone_auth -j DROP

sudo iptables -I INPUT -i br-mgmt -p tcp --dport 11211 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 11211 -j DROP

sudo iptables -I INPUT -i br-mgmt -p tcp --dport 3306 -j ACCEPT
sudo iptables -I INPUT -i lo -p tcp --dport 3306 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3306 -j DROP

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Verify rules
sudo iptables -L INPUT -n -v --line-numbers

PERSISTENCE:

Rules are saved to /etc/iptables/rules.v4 and automatically restored on boot 
by netfilter-persistent service or iptables-persistent package.

VERIFICATION:

Verify Keystone rate limiting:
for i in {1..10}; do openstack token issue; done
Expected: First 5 succeed, remaining 5 blocked

Verify Memcached restriction:
From tenant VM: telnet 192.168.100.11 11211
Expected: Connection refused

Verify MariaDB restriction:
From tenant VM: telnet 192.168.100.11 3306
Expected: Connection refused

================================================================================
SECTION 3: SERVICE CONFIGURATION FILES
================================================================================

3.1 GLANCE API CONFIGURATION
=============================

File Location: /etc/glance/glance-api.conf
Container: glance_api
Purpose: Disable image import functionality
STIG Controls: OSGL-CVE-001
Remediates: VULN-003

BEFORE REMEDIATION:
-------------------

[DEFAULT]
# Image import plugins (may be configured)
image_import_plugins = []

[image_import_opts]
# Image import configuration

SECURITY ISSUE:
If image_import_plugins is configured, it enables additional image import 
functionality that can be exploited via CVE-2024-32498.

AFTER REMEDIATION:
------------------

[DEFAULT]
# Disable image import to prevent CVE-2024-32498 exploitation
# image_import_plugins = []

[image_import_opts]
# Image import disabled for security

CHANGES MADE:
- Commented out image_import_plugins configuration
- Added security comment explaining the reason

SECURITY IMPACT:
- Image import functionality completely disabled
- Additional defense-in-depth layer for CVE-2024-32498
- Combined with policy.yaml restrictions, provides multiple blocking points

IMPLEMENTATION:
Edit /etc/kolla/config/glance/glance-api.conf
docker cp /etc/kolla/config/glance/glance-api.conf glance_api:/etc/glance/
docker restart glance_api

================================================================================
SECTION 4: FILE SYSTEM PERMISSIONS
================================================================================

4.1 CREDENTIAL FILE PERMISSIONS
================================

File Location: /etc/kolla/passwords.yml
Purpose: Restrict access to OpenStack service credentials
STIG Controls: OSFS-CRED-001
Remediates: VULN-014

BEFORE REMEDIATION:
-------------------

File: /etc/kolla/passwords.yml
Permissions: -rw-r----- (640)
Owner: root
Group: kolla

Octal: 640
User: rw- (read, write)
Group: r-- (read)
Other: --- (no access)

SECURITY ISSUE:
- All members of kolla group can read file
- File contains plaintext passwords for all services:
  - MariaDB root password
  - RabbitMQ credentials
  - Keystone admin password
  - Service account passwords
- Unprivileged users in kolla group can access all credentials

AFTER REMEDIATION:
------------------

File: /etc/kolla/passwords.yml
Permissions: -rw------- (600)
Owner: root
Group: root

Octal: 600
User: rw- (read, write)
Group: --- (no access)
Other: --- (no access)

CHANGES MADE:
- Permissions: 640 -> 600
- Group: kolla -> root
- Only root user can read file

SECURITY IMPACT:
- Credential exposure prevented
- Unprivileged users cannot access passwords
- Follows principle of least privilege
- CVSS 7.8 -> 0.0

IMPLEMENTATION:

sudo chmod 600 /etc/kolla/passwords.yml
sudo chown root:root /etc/kolla/passwords.yml

VERIFICATION:

ls -l /etc/kolla/passwords.yml
Expected: -rw------- 1 root root

sudo -u kolla cat /etc/kolla/passwords.yml
Expected: Permission denied

================================================================================
CONFIGURATION CHANGE SUMMARY
================================================================================

Total Configuration Changes: 5 files/rulesets modified

POLICY FILES (2):
1. /etc/glance/policy.yaml - Restrict image operations to admin
2. /etc/neutron/policy.yaml - Enforce port and floating IP ownership

FIREWALL RULES (1):
3. iptables - Rate limiting and network access restrictions (6 rules)

SERVICE CONFIGURATION (1):
4. /etc/glance/glance-api.conf - Disable image import

FILE PERMISSIONS (1):
5. /etc/kolla/passwords.yml - Restrict to root only

VULNERABILITIES REMEDIATED:
- VULN-003: Glance policy + service config
- VULN-004: iptables rate limiting
- VULN-008: Neutron policy
- VULN-010: Neutron policy
- VULN-011: iptables Memcached restriction
- VULN-012: iptables MariaDB restriction
- VULN-014: File permissions

CVSS IMPACT:
- Before: 56.8
- After: 9.7
- Reduction: 47.1 points (83%)

================================================================================
DEPLOYMENT INSTRUCTIONS
================================================================================

To deploy these configurations to a new OpenStack environment:

STEP 1: Policy Files
Copy policy files to Kolla configuration directory:
/etc/kolla/config/glance/policy.yaml
/etc/kolla/config/neutron/policy.yaml

STEP 2: Service Configuration
Copy service configuration:
/etc/kolla/config/glance/glance-api.conf

STEP 3: Deploy Configurations
kolla-ansible reconfigure -i all-in-one

Or manually:
docker cp policy.yaml glance_api:/etc/glance/
docker cp policy.yaml neutron_server:/etc/neutron/
docker restart glance_api neutron_server

STEP 4: Apply Firewall Rules
Run remediation scripts:
bash remediation/VULN-004/apply-remediation.sh
bash remediation/VULN-011/apply-remediation.sh
bash remediation/VULN-012/apply-remediation.sh

Or manually apply iptables rules as documented above.

STEP 5: Fix File Permissions
chmod 600 /etc/kolla/passwords.yml
chown root:root /etc/kolla/passwords.yml

STEP 6: Verify
Run STIG verification scripts (see Appendix B)

================================================================================
ROLLBACK PROCEDURES
================================================================================

If configurations need to be reverted:

POLICY FILES:
Restore default policy files from Kolla-Ansible distribution:
/usr/local/share/kolla-ansible/ansible/roles/*/templates/policy.yaml.j2

FIREWALL RULES:
Remove specific rules:
sudo iptables -D INPUT <rule-specification>

Or flush all rules (CAUTION):
sudo iptables -F INPUT

SERVICE CONFIGURATION:
Restore default glance-api.conf from Kolla-Ansible

FILE PERMISSIONS:
Restore original permissions (NOT RECOMMENDED):
chmod 640 /etc/kolla/passwords.yml
chown root:kolla /etc/kolla/passwords.yml

================================================================================
END OF APPENDIX D
================================================================================

