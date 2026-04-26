================================================================================
STIG Control V-006: OSNT-FIP-001
Neutron Floating IP Ownership Validation
================================================================================

STIG ID: OSNT-FIP-001
Severity: CAT I
Rule Title: OpenStack Neutron must enforce floating IP ownership to prevent cross-tenant IP hijacking

Vulnerability Discussion:

Floating IP hijacking allows users to assign floating IPs belonging to other tenants to their own instances. This enables IP address theft, bypasses network access controls, and violates tenant isolation.

Without proper ownership validation in Neutron policy, users can associate any floating IP they can discover to their own ports and instances, regardless of the floating IP's project_id. This creates a severe security vulnerability that violates the fundamental multi-tenancy model of OpenStack.

Attack Scenario:

1. Attacker (User A) authenticates to Project A
2. Attacker lists floating IPs in the system
3. Attacker identifies floating IP belonging to Victim (User B) in Project B
4. Attacker creates port in own project (Project A)
5. Attacker executes: openstack floating ip set --port <attacker-port> <victim-floating-ip>
6. Neutron allows association due to insufficient ownership check
7. Victim's floating IP is now assigned to attacker's instance
8. Attacker gains external network access using victim's IP address
9. Victim loses external connectivity
10. Network access controls based on IP address are bypassed

Impact:
- IP address theft and spoofing
- Bypass of firewall rules and IP-based access controls
- Denial of service against victim tenant
- Violation of multi-tenancy isolation
- Potential for man-in-the-middle attacks

CVSS 3.1 Score: 6.5 (Medium)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N

Check Text:

Verify Neutron policy enforces floating IP ownership validation for association operations.

Method 1: Automated Verification
Run the verification script:

    bash ~/openstack-security-assessment/stig-verification/stig-verification-neutron-fip.sh

Expected: Cross-tenant floating IP association blocked, returns PASS

Method 2: Manual Policy Check
Check Neutron policy configuration:

    sudo docker exec neutron_server cat /etc/neutron/policy.yaml | grep -A1 "update_floatingip"

Expected output:
    "update_floatingip": "rule:admin_or_owner and rule:owner"

Method 3: Functional Test
Test cross-tenant floating IP association is blocked:

    # Create floating IP in victim project
    source ~/victim-openrc.sh
    VICTIM_FIP=$(openstack floating ip create public -f value -c id)
    
    # Create port in attacker project
    source ~/attacker-openrc.sh
    ATTACKER_PORT=$(openstack port create --network demo-network attacker-port -f value -c id)
    
    # Attempt to associate victim's floating IP to attacker's port
    openstack floating ip set --port $ATTACKER_PORT $VICTIM_FIP

Expected: Error - "You are not authorized" or "Policy doesn't allow update_floatingip"

Verify floating IP is not associated:

    source ~/victim-openrc.sh
    openstack floating ip show $VICTIM_FIP | grep port_id

Expected: port_id should be None (not associated)

Fix Text:

Step 1: Create Neutron Policy Configuration

Create policy file with strict ownership enforcement:

    sudo docker exec -u root neutron_server bash -c 'cat > /etc/neutron/policy.yaml << "POLICY"
    "context_is_admin": "role:admin"
    "owner": "tenant_id:%(tenant_id)s"
    "admin_or_owner": "rule:context_is_admin or rule:owner"
    "delete_port": "rule:admin_or_owner and rule:owner"
    "update_port": "rule:admin_or_owner and rule:owner"
    "update_floatingip": "rule:admin_or_owner and rule:owner"
    "get_port": ""
    "create_port": ""
    "get_floatingip": ""
    "create_floatingip": ""
    POLICY'

Note: The -u root flag is required for write permissions inside container

Step 2: Enable Policy Enforcement

Ensure Neutron uses the policy file:

    sudo docker exec -u root neutron_server bash -c 'if ! grep -q "\[oslo_policy\]" /etc/neutron/neutron.conf; then
        echo "" >> /etc/neutron/neutron.conf
        echo "[oslo_policy]" >> /etc/neutron/neutron.conf
        echo "policy_file = /etc/neutron/policy.yaml" >> /etc/neutron/neutron.conf
    fi'

Step 3: Restart Neutron Server

Apply configuration:

    sudo docker restart neutron_server
    sleep 15

Step 4: Verify Service Status

    sudo docker ps | grep neutron_server

Expected: Container in "Up" status

Step 5: Verify Remediation

Test cross-tenant floating IP association is blocked:

    source ~/victim-openrc.sh
    TEST_FIP=$(openstack floating ip create public -f value -c id)
    
    source ~/attacker-openrc.sh
    TEST_PORT=$(openstack port create --network demo-network test-port -f value -c id)
    openstack floating ip set --port $TEST_PORT $TEST_FIP

Expected: 403 Forbidden or Policy violation error

Verify floating IP remains unassociated:

    source ~/victim-openrc.sh
    openstack floating ip show $TEST_FIP | grep port_id

Expected: None (association was blocked)

Cleanup:

    openstack floating ip delete $TEST_FIP
    source ~/attacker-openrc.sh
    openstack port delete $TEST_PORT

Automated Remediation Script:

For automated application of this control, execute:

    bash ~/openstack-security-assessment/remediation/VULN-010/apply-remediation.sh

Defense-in-Depth:

This control should be combined with:
- OSNT-PORT-001: Port ownership enforcement
- Network monitoring for floating IP associations
- Alerting on cross-tenant access attempts
- Regular audit of floating IP assignments
- IP address management (IPAM) tracking

CCI: CCI-000213, CCI-002235

NIST 800-53 Mappings:
- AC-3: Access Enforcement
- AC-3(7): Access Enforcement - Role-Based Access Control
- AC-6: Least Privilege
- AC-6(1): Least Privilege - Authorize Access to Security Functions
- SC-7: Boundary Protection

CVSS Before: 6.5 (Medium)
CVSS After: 0.0 (Remediated)
Reduction: 6.5 points (100%)

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

================================================================================
