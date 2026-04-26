================================================================================
STIG Control V-003: OSKS-AUTH-001
Keystone Authentication Rate Limiting
================================================================================

STIG ID: OSKS-AUTH-001
Severity: CAT II
Rule Title: OpenStack Keystone must implement rate limiting to prevent brute force authentication attacks

Vulnerability Discussion:

Without rate limiting, Keystone authentication endpoint is vulnerable to brute force password guessing attacks. An attacker can attempt unlimited authentication requests to guess user passwords, service account credentials, or application credentials.

Keystone does not implement native rate limiting. The authentication API at port 5000 processes all incoming requests without throttling, allowing attackers to:
- Attempt thousands of password combinations per minute
- Target multiple user accounts simultaneously
- Exploit weak passwords through dictionary attacks
- Bypass account lockout policies through distributed attacks
- Launch distributed brute force attacks from multiple source IPs

Rate limiting with iptables hashlimit module restricts authentication attempts to 5 per minute per source IP, significantly reducing brute force attack effectiveness while allowing legitimate authentication.

Attack Scenario:

1. Attacker identifies valid OpenStack usernames through reconnaissance
2. Prepares dictionary of common passwords and variations
3. Launches automated brute force attack against Keystone API (port 5000)
4. Without rate limiting: 1000+ attempts per minute possible
5. Successful authentication grants access to victim account
6. Attacker escalates privileges or accesses sensitive resources

CVSS 3.1 Score: 7.5 (High)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Check Text:

Verify iptables rate limiting is configured for Keystone authentication endpoint (port 5000).

Method 1: Automated Verification
Run the verification script:

    bash ~/openstack-security-assessment/stig-verification/stig-verification-keystone-ratelimit.sh

Expected: All checks return PASS status

Method 2: Manual Verification
Check iptables rules for Keystone port 5000:

    sudo iptables -L INPUT -n -v --line-numbers | grep 5000

Expected output should show:
- Rule with hashlimit module
- Rate limit of 5/min
- LOG action for rate-limited requests
- DROP action for requests exceeding limit

Detailed check:

    sudo iptables -L INPUT -n -v | grep -A2 "dpt:5000"

Expected:
    pkts bytes target     prot opt in     out     source               destination
       0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5000 state NEW limit: above 5/min
       0     0 LOG        tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5000 state NEW limit: above 5/min LOG flags 0 level 4 prefix "KEYSTONE_RATE_LIMIT: "

Verify rules are persistent:

    sudo cat /etc/iptables/rules.v4 | grep 5000

Expected: Rules should be present in saved configuration

Fix Text:

Step 1: Install iptables-persistent (if not already installed)

    sudo apt-get update
    sudo apt-get install -y iptables-persistent

Step 2: Configure Rate Limiting Rules for Keystone

Create rate limiting rules with logging:

    sudo iptables -I INPUT -p tcp --dport 5000 -m state --state NEW \
      -m hashlimit --hashlimit-above 5/min --hashlimit-mode srcip \
      --hashlimit-name keystone_auth -j LOG --log-prefix "KEYSTONE_RATE_LIMIT: "

    sudo iptables -I INPUT -p tcp --dport 5000 -m state --state NEW \
      -m hashlimit --hashlimit-above 5/min --hashlimit-mode srcip \
      --hashlimit-name keystone_auth -j DROP

Explanation:
- First rule: Logs attempts that exceed rate limit
- Second rule: Drops requests exceeding 5 per minute per source IP
- hashlimit-mode srcip: Tracks rate per source IP address
- hashlimit-name keystone_auth: Names the tracking table

Step 3: Save iptables Rules

Persist rules across reboots:

    sudo mkdir -p /etc/iptables
    sudo iptables-save > /etc/iptables/rules.v4

For systemd systems, ensure iptables-persistent service is enabled:

    sudo systemctl enable netfilter-persistent
    sudo systemctl start netfilter-persistent

Step 4: Verify Configuration

Check rules are active:

    sudo iptables -L INPUT -n -v | grep 5000

Test rate limiting (optional):

    for i in {1..10}; do 
      curl -s http://192.168.100.11:5000/v3 > /dev/null
      echo "Request $i completed"
    done

After 5 requests within a minute, subsequent requests should be dropped.

Check logs for rate-limited attempts:

    sudo tail -f /var/log/syslog | grep KEYSTONE_RATE_LIMIT

Automated Remediation Script:

For automated application of this control, execute:

    bash ~/openstack-security-assessment/remediation/VULN-004/apply-remediation.sh

Monitoring and Alerting:

Monitor rate-limiting logs for potential attack patterns:

    sudo grep "KEYSTONE_RATE_LIMIT" /var/log/syslog | tail -20

Set up alerting for repeated rate limit violations:

    sudo grep "KEYSTONE_RATE_LIMIT" /var/log/syslog | wc -l

If count exceeds threshold, investigate source IPs and block if necessary.

Limitations:

Rate limiting at network layer has limitations:
- Distributed attacks from multiple IPs can still attempt 5/min each
- Legitimate users behind NAT may share source IP
- Application-layer rate limiting (within Keystone) would be more granular

This control provides defense-in-depth but should be combined with:
- Strong password policies
- Account lockout mechanisms
- Multi-factor authentication where possible
- Monitoring and alerting for authentication failures

CCI: CCI-000044, CCI-001094

NIST 800-53 Mappings:
- AC-7: Unsuccessful Logon Attempts
- AC-7(1): Automatic Account Lock
- SC-5: Denial of Service Protection
- SC-5(1): Denial of Service Protection - Restrict Ability to Attack

CVSS Before: 7.5 (High)
CVSS After: 4.3 (Medium)
Reduction: 3.2 points (43%)

Note: Residual risk remains due to distributed attack potential and NAT scenarios.

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

================================================================================
