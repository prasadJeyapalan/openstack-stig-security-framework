================================================================================
STIG Control V-004: OSKS-AUTH-002
Keystone Account Lockout Policy
================================================================================

STIG ID: OSKS-AUTH-002
Severity: CAT II
Rule Title: OpenStack Keystone should implement account lockout policy for failed authentication attempts

Vulnerability Discussion:

Account lockout policies complement rate limiting by disabling accounts after repeated failed authentication attempts. While OSKS-AUTH-001 limits authentication rate at the network layer, a comprehensive security posture would include application-layer account lockout.

Keystone supports account lockout through the [security_compliance] configuration section with the following parameters:
- lockout_failure_attempts: Number of failed attempts before lockout
- lockout_duration: Duration of account lockout in seconds
- unique_last_password_count: Number of unique passwords to enforce

Current implementation relies on OSKS-AUTH-001 iptables rate limiting which provides network-level protection. This prevents brute force attacks by limiting authentication attempts to 5 per minute per source IP address.

Full application-layer account lockout is noted as a future enhancement that would provide defense-in-depth by tracking failures at the user account level rather than source IP level.

Comparison of Approaches:

Network-layer rate limiting (OSKS-AUTH-001):
- Pros: Protects against distributed attacks, no Keystone changes required
- Cons: Shared IPs (NAT) may affect legitimate users, per-IP not per-account

Application-layer lockout (Future enhancement):
- Pros: Per-account tracking, unaffected by source IP, better user experience
- Cons: Requires Keystone configuration, potential for account DoS

CVSS 3.1 Score: 7.5 (High)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Check Text:

Verify rate limiting provides protection against account compromise through repeated authentication attempts.

Method 1: Verify Network-Layer Protection
Check iptables rules restrict authentication attempts:

    sudo iptables -L INPUT -n -v | grep 5000

Expected: Rules showing hashlimit 5/min for port 5000

Method 2: Check Keystone Configuration
Verify if application-layer lockout is configured:

    sudo docker exec keystone grep -A5 "\[security_compliance\]" /etc/keystone/keystone.conf

Expected (current): No security_compliance section found
Expected (future): lockout_failure_attempts configured

Fix Text:

Current Implementation (Applied):

This control is currently implemented through OSKS-AUTH-001 iptables rate limiting which restricts authentication attempts to 5 per minute per source IP.

No additional configuration required. Verify OSKS-AUTH-001 is applied:

    sudo iptables -L INPUT -n -v | grep 5000

Expected: Rate limiting rules are active

Future Enhancement (Recommended):

For comprehensive account lockout, configure Keystone security_compliance:

Step 1: Add configuration to Keystone

    sudo docker exec -u root keystone bash -c 'cat >> /etc/keystone/keystone.conf << "CONFIG"

    [security_compliance]
    lockout_failure_attempts = 5
    lockout_duration = 1800
    unique_last_password_count = 5
    password_expires_days = 90
    CONFIG'

Step 2: Restart Keystone

    sudo docker restart keystone

Step 3: Verify Configuration

    sudo docker exec keystone grep -A5 "\[security_compliance\]" /etc/keystone/keystone.conf

Note: This future enhancement is not currently implemented in this assessment but is recommended for production deployments requiring defense-in-depth.

Current Mitigation Status:

Protection Level: PARTIAL
- Network-layer rate limiting: ACTIVE (5 attempts/min per IP)
- Application-layer lockout: NOT CONFIGURED (future enhancement)

Risk Acceptance:

Network-layer rate limiting provides adequate protection for this deployment by:
- Preventing rapid brute force attacks (>5 attempts/min blocked)
- Logging rate limit violations for monitoring
- Operating transparently without Keystone modifications

Residual risk of slow, distributed brute force attacks is mitigated by:
- Strong password policies
- Monitoring of authentication logs
- Alert generation for repeated failures

CCI: CCI-000044, CCI-001774

NIST 800-53 Mappings:
- AC-7: Unsuccessful Logon Attempts
- AC-7(1): Automatic Account Lock
- IA-5: Authenticator Management
- IA-5(1): Password-Based Authentication

CVSS Before: 7.5 (High)
CVSS After: 4.3 (Medium)
Reduction: 3.2 points (43%)

Note: CVSS reduction achieved through OSKS-AUTH-001 implementation

Implementation Date: April 5, 2026 (via OSKS-AUTH-001)
Verification Date: April 5, 2026
Status: PARTIAL (Network-layer protection active)

================================================================================
