================================================================================
STIG Control V-005: OSNT-PORT-001
Neutron Port Access Control
================================================================================

STIG ID: OSNT-PORT-001
Severity: CAT I
Rule Title: OpenStack Neutron must enforce port ownership to prevent cross-tenant port manipulation

Vulnerability Discussion:

Neutron port deletion vulnerability allows users to delete network ports belonging to other tenants. This violates multi-tenancy isolation and enables denial of service attacks against other tenants' virtual machines.

Without proper ownership validation, the default Neutron policy allows any user matching admin_or_owner rule to delete ports. The owner rule checks tenant_id but does not enforce that the port's project_id matches the requesting user's project_id for modification operations.

An attacker with valid credentials in one project can:
1. List all ports in the system (some visibility across tenants)
2. Identify target tenant's port UUID through reconnaissance
3. Execute delete command on victim's port
4. Cause victim's VM to lose network connectivity immediately
5. Disrupt victim's services and operations

This violates cloud multi-tenancy security model and enables cross-tenant denial of service attacks. The vulnerability affects both port deletion and port modification operations.

Attack Scenario:

1. Attacker authenticates as member user in Project A
2. Creates test port in own project to understand port structure
3. Uses educated guessing or reconnaissance to identify victim port UUID in Project B
4. Executes: openstack port delete <victim-port-uuid>
5. Neutron policy allows deletion due to insufficient ownership check
6. Victim's VM in Project B loses network connectivity
7. Victim experiences service disruption

CVSS 3.1 Score: 7.1 (High)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L

Check Text:

Verify Neutron policy enforces port ownership for delete and update operations.

Method 1: Automated Verification
Run the verification script:

    bash ~/openstack-security-assessment/stig-verification/stig-verification-neutron-port.sh

Expected: Cross-tenant port deletion blocked, returns PASS

Method 2: Manual Policy Check
Check Neutron policy configuration:

    sudo docker exec neutron_server cat /etc/neutron/policy.yaml | grep -A2 "delete_port\|update_port"

Expected output should show:
    "delete_port": "rule:admin_or_owner and rule:owner"
    "update_port": "rule:admin_or_owner and rule:owner"
    "owner": "tenant_id:%(tenant_id)s"

Method 3: Functional Test
Test cross-tenant deletion is blocked:

    # Create port in victim project
    source ~/victim-openrc.sh
    VICTIM_PORT=$(openstack port create --network demo-network victim-test-port -f value -c id)

    # Attempt deletion from attacker project
    source ~/attacker-openrc.sh
    openstack port delete $VICTIM_PORT

Expected: Error - "You are not authorized" or "Policy doesn't allow delete_port"

Verify port still exists:

    source ~/victim-openrc.sh
    openstack port show $VICTIM_PORT

Expected: Port details displayed (not deleted)

Fix Text:

Step 1: Create Neutron Policy Configuration

Create policy file to enforce strict ownership checks:

    sudo docker exec -u root neutron_server bash -c 'cat > /etc/neutron/policy.yaml << "POLICY"
    "context_is_admin": "role:admin"
    "owner": "tenant_id:%(tenant_id)s"
    "admin_or_owner": "rule:context_is_admin or rule:owner"
    "delete_port": "rule:admin_or_owner and rule:owner"
    "update_port": "rule:admin_or_owner and rule:owner"
    "get_port": ""
    "create_port": ""
    POLICY'

Note: The -u root flag is required for write permissions inside container

Step 2: Enable Policy Enforcement

Ensure Neutron is configured to use the policy file:

    sudo docker exec -u root neutron_server bash -c 'if ! grep -q "\[oslo_policy\]" /etc/neutron/neutron.conf; then
        echo "" >> /etc/neutron/neutron.conf
        echo "[oslo_policy]" >> /etc/neutron/neutron.conf
        echo "policy_file = /etc/neutron/policy.yaml" >> /etc/neutron/neutron.conf
    fi'

Step 3: Restart Neutron Server

Apply configuration changes:

    sudo docker restart neutron_server

Wait for service to be ready:

    sleep 15

Step 4: Verify Service Status

Confirm Neutron is running:

    sudo docker ps | grep neutron_server

Expected: Container in "Up" status

Step 5: Verify Remediation

Test that cross-tenant port deletion is blocked:

    source ~/victim-openrc.sh
    TEST_PORT=$(openstack port create --network demo-network test-port -f value -c id)

    source ~/attacker-openrc.sh
    openstack port delete $TEST_PORT

Expected: 403 Forbidden or Policy violation error

Verify port still exists:

    source ~/victim-openrc.sh
    openstack port show $TEST_PORT

Expected: Port details shown (deletion was blocked)

Cleanup:

    openstack port delete $TEST_PORT

Automated Remediation Script:

For automated application of this control, execute:

    bash ~/openstack-security-assessment/remediation/VULN-008/apply-remediation.sh

Defense-in-Depth:

This control should be applied with:
- Network segmentation between projects
- Monitoring of port deletion/modification events
- Alerting on cross-tenant access attempts
- Regular audit of Neutron policy configurations

CCI: CCI-000213, CCI-002235

NIST 800-53 Mappings:
- AC-3: Access Enforcement
- AC-3(7): Access Enforcement - Role-Based Access Control
- AC-6: Least Privilege
- AC-6(1): Least Privilege - Authorize Access to Security Functions

CVSS Before: 7.1 (High)
CVSS After: 0.0 (Remediated)
Reduction: 7.1 points (100%)

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

================================================================================
