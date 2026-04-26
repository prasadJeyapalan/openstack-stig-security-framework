================================================================================
STIG Control V-011: OSFS-AUDIT-001
Credential File Access Auditing
================================================================================

STIG ID: OSFS-AUDIT-001
Severity: CAT II
Rule Title: Access attempts to credential files must be logged for security monitoring

Vulnerability Discussion:

Auditing access to credential files provides detection capability for unauthorized access attempts and compliance evidence. Even with proper file permissions (OSFS-CRED-001), logging access attempts enables security teams to identify reconnaissance activity, potential compromise attempts, and insider threats.

Without access logging, security teams cannot:
- Detect unauthorized access attempts to credentials
- Identify compromised accounts attempting privilege escalation
- Investigate security incidents involving credential theft
- Prove compliance with access control policies
- Establish forensic timelines for incident response

Access logging should capture:
- Read attempts (both successful and failed)
- Write operations (credential updates)
- Attribute changes (permission modifications)
- Ownership changes
- File deletion attempts
- All user identities performing operations

This provides forensic evidence, enables real-time alerting, and supports incident response activities.

Use Cases for Audit Logs:

1. Intrusion Detection:
   - Detect multiple failed read attempts (reconnaissance)
   - Identify unexpected users accessing credentials
   - Alert on access outside normal operational hours

2. Incident Response:
   - Determine when credentials were accessed
   - Identify which accounts accessed the file
   - Establish timeline of credential compromise

3. Compliance:
   - Prove access controls are effective
   - Document who accessed sensitive files
   - Demonstrate audit trail for regulatory requirements

4. Insider Threat Detection:
   - Monitor privileged user activity
   - Detect credential harvesting by administrators
   - Identify suspicious access patterns

CVSS 3.1 Score: N/A (Audit and monitoring control, not a vulnerability)

Check Text:

Verify auditd is installed and running, and rules monitor /etc/kolla/passwords.yml.

Method 1: Check Auditd Service Status

    sudo systemctl status auditd

Expected: active (running)

Method 2: Verify Audit Rules

    sudo auditctl -l | grep passwords.yml

Expected output:
    -w /etc/kolla/passwords.yml -p rwa -k credential_access

Method 3: Verify Persistent Rules

    sudo cat /etc/audit/rules.d/openstack.rules | grep passwords.yml

Expected:
    -w /etc/kolla/passwords.yml -p rwa -k credential_access

Method 4: Test Audit Logging
Generate test access and verify it is logged:

    # Generate access event
    sudo cat /etc/kolla/passwords.yml > /dev/null

    # Search audit log
    sudo ausearch -k credential_access -ts recent

Expected: Audit record showing the access attempt with timestamp, user, and action

Method 5: Check Audit Log Rotation

    ls -la /var/log/audit/

Expected: audit.log present, rotation configured

Fix Text:

Step 1: Install auditd (if not already installed)

    sudo apt-get update
    sudo apt-get install -y auditd audispd-plugins

Step 2: Enable and Start Auditd Service

    sudo systemctl enable auditd
    sudo systemctl start auditd

Step 3: Create OpenStack Audit Rules

Create audit rules file for OpenStack credential monitoring:

    sudo mkdir -p /etc/audit/rules.d

    sudo bash -c 'cat > /etc/audit/rules.d/openstack.rules << "AUDITRULES"
    # Monitor OpenStack credential file access
    -w /etc/kolla/passwords.yml -p rwa -k credential_access
    
    # Monitor policy file changes
    -w /etc/glance/policy.yaml -p wa -k policy_change
    -w /etc/neutron/policy.yaml -p wa -k policy_change
    
    # Monitor configuration changes
    -w /etc/kolla/ -p wa -k kolla_config_change
    AUDITRULES'

Explanation of flags:
- -w: Watch file or directory
- -p r: Log read access
- -p w: Log write access
- -p a: Log attribute changes
- -k: Key/tag for searching logs

Step 4: Load Audit Rules

    sudo augenrules --load

Alternative if augenrules not available:

    sudo auditctl -w /etc/kolla/passwords.yml -p rwa -k credential_access

Step 5: Verify Rules Are Active

    sudo auditctl -l | grep -E "passwords.yml|policy.yaml|kolla"

Expected: All configured watch rules displayed

Step 6: Test Audit Logging

Generate test access:

    sudo cat /etc/kolla/passwords.yml > /dev/null

Search for the event:

    sudo ausearch -k credential_access -ts recent

Expected: Audit record showing access with details

Step 7: Configure Log Rotation (Optional)

Edit auditd configuration for appropriate retention:

    sudo nano /etc/audit/auditd.conf

Recommended settings:
    max_log_file = 100
    num_logs = 10
    max_log_file_action = ROTATE

Step 8: Set Up Real-Time Alerting (Optional)

Configure audisp to forward critical events:

    sudo nano /etc/audisp/plugins.d/syslog.conf

Set active = yes to forward audit events to syslog

Monitoring and Analysis:

Search for credential access attempts:

    sudo ausearch -k credential_access

Search by user:

    sudo ausearch -k credential_access -ui 1000

Search by time range:

    sudo ausearch -k credential_access -ts today

Search for failed access attempts:

    sudo ausearch -k credential_access | grep denied

Generate summary report:

    sudo aureport -k

Alert on Suspicious Activity:

Create monitoring script for unauthorized access:

    sudo bash -c 'cat > /usr/local/bin/check-credential-access.sh << "SCRIPT"
    #!/bin/bash
    # Check for credential file access in last hour
    EVENTS=$(sudo ausearch -k credential_access -ts recent | grep -c "type=SYSCALL")
    if [ "$EVENTS" -gt 10 ]; then
        echo "WARNING: $EVENTS credential file access events detected"
        # Send alert via email, syslog, etc.
    fi
    SCRIPT'

    sudo chmod +x /usr/local/bin/check-credential-access.sh

Schedule via cron:

    echo "0 * * * * /usr/local/bin/check-credential-access.sh" | sudo crontab -

Integration with Defense-in-Depth:

This audit control complements:
- OSFS-CRED-001: File permissions prevent unauthorized access
- This control: Logs all access attempts (authorized and unauthorized)
- Result: Prevention + Detection = Complete security posture

Even if permissions are bypassed:
- Access attempts are logged
- Security team receives alerts
- Incident response can begin immediately

CCI: CCI-000172, CCI-001814, CCI-000366

NIST 800-53 Mappings:
- AU-2: Event Logging
- AU-2(3): Event Logging - Reviews and Updates
- AU-3: Content of Audit Records
- AU-6: Audit Review, Analysis, and Reporting
- AU-9: Protection of Audit Information
- AU-12: Audit Generation

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: RECOMMENDED (Not required for basic remediation, enhances security posture)

Note: This is a detective control that complements preventive controls (OSFS-CRED-001). Recommended for production deployments requiring comprehensive security monitoring.

================================================================================
