# Appendix C: Test Scripts

## Overview

This appendix contains all manual test scripts developed for the security assessment of the Kolla-Ansible OpenStack deployment. These scripts were used to validate vulnerabilities during the assessment phase and verify remediation effectiveness after STIG control implementation.

**Total Test Scripts:** 25
- Authentication Tests: 10 scripts
- Image Service Tests: 5 scripts  
- Network Tests: 4 scripts (includes 2 comprehensive network exposure tests)
- Cache/Database Tests: 4 scripts
- Supporting Scripts: 2 scripts

---

## Critical Network Exposure Tests

### test-memcached-network-exposure.sh
**Vulnerability:** VULN-011 - Memcached Network Exposure  
**CVSS Score:** 9.1 (Critical)  
**Purpose:** Comprehensive validation of Memcached network exposure and token extraction

**Test Phases:**
1. Network Connectivity Test - TCP connection to port 11211
2. Cache Statistics Retrieval - Uptime, connections, items
3. Token Extraction and Analysis - Discovers slabs, extracts tokens, parses metadata

**Test Results (Vulnerable State):**
- Slabs discovered: 16
- Total keys found: 22
- Token-like keys: 20
- Complete tokens extracted: 5

**Impact:**
- Complete authentication bypass
- Admin token theft with usable token values
- Session hijacking
- Direct API access without passwords

**STIG Control:** OSCACHE-001  
**Expected Result (After):** Connection refused (firewall blocks port 11211)

---

### test-mariadb-network-exposure.sh
**Vulnerability:** VULN-012 - MariaDB Network Exposure  
**CVSS Score:** 10.0 (Critical)  
**Purpose:** Comprehensive validation of MariaDB network exposure and database enumeration

**Test Phases:**
1. Network Connectivity Test - TCP connection to port 3306
2. MySQL Protocol Analysis - Version, capabilities, SSL support
3. Database Enumeration - Uses credentials from CVE-2024-32498

**Test Results (Vulnerable State):**
- Server Version: 5.5.5-10.11.15-MariaDB
- Protocol Version: 10
- OpenStack Databases Found: 8 (keystone, nova, glance, neutron, cinder, placement, nova_api, nova_cell0)
- User table structure: Extracted
- Password hashes: Accessible
- Projects extracted: 9 (admin, demo-project, network-victim, etc.)

**Impact:**
- Complete database compromise
- All OpenStack credentials at risk
- User password hashes can be cracked offline

**Attack Chain (VULN-003 + VULN-012):**
1. Exploit CVE-2024-32498 to extract database password
2. Connect to exposed MariaDB using stolen password
3. Enumerate all databases and extract password hashes

**STIG Control:** OSDB-NET-001  
**Expected Result (After):** Connection refused (firewall blocks port 3306)

---

## Authentication Security Tests

### test-keystone-auth-bypass.sh
**Purpose:** Tests for authentication bypass via token cache
**Test Phases:**
1. Connect to Memcached from tenant network
2. Retrieve cached tokens
3. Use stolen tokens for API access

**STIG Control:** OSCACHE-001

---

### test-keystone-user-creation-attack.sh
**Purpose:** Tests unauthorized user creation
**Test Phases:**
1. Authenticate as non-admin
2. Attempt user creation
3. Verify operation blocked

---

### test-manual-token-revocation.sh
**Purpose:** Tests token revocation functionality
**Test Phases:**
1. Create valid token
2. Revoke token
3. Verify revoked token rejected

---

### test-token-forgery.sh
**Purpose:** Tests token forgery attempts
**Test Phases:**
1. Analyze token structure
2. Attempt forgery
3. Verify rejection

---

### test-token-lifetime.sh
**Purpose:** Validates token expiration
**Test Phases:**
1. Create token
2. Wait for expiration
3. Verify expired token rejected

---

### test-revoke-vs-disable-comparison.sh
**Purpose:** Compares revocation vs disabling

---

### test-disabled-user.sh
**Purpose:** Tests disabled user behavior

---

### test-exploit-5min-window.sh
**Purpose:** Tests timing window exploitation

---

### test-5min-persistence-attack.sh
**Purpose:** Tests attack persistence

---

### test-5min-persistence-attack-v2.sh
**Purpose:** Enhanced persistence testing

---

## Image Service Tests

### test-cve-2024-32498-qcow2.sh
**Vulnerability:** VULN-003 - CVE-2024-32498  
**CVSS Score:** 8.8 (High)  
**Purpose:** Comprehensive CVE-2024-32498 exploitation

**Test Phases:**
1. Direct QCOW2 upload (safety check test)
2. RAW bypass (local conversion)
3. Credential exfiltration (126 credentials)
4. Image conversion attack

**Test Results:**
- Total credentials extracted: 126
- Database passwords: 35
- Keystone passwords: 29
- Private keys: 7

**STIG Control:** OSGL-CVE-001

---

### test-cve-2024-32498-qcow2-v2.sh
**Purpose:** Refined version of CVE test

---

### test-cve-2024-32498-attack-chain.sh
**Purpose:** Demonstrates complete attack chain

---

### test-unauthorized-image-deletion.sh
**Purpose:** Tests cross-project image deletion

---

### test-glance-image-quota.sh
**Purpose:** Validates quota enforcement

---

## Network Security Tests

### test-neutron-port-isolation.sh
**Vulnerability:** VULN-008 - Cross-Tenant Port Deletion  
**CVSS Score:** 7.1 (High)  
**Purpose:** Tests unauthorized port deletion

**STIG Control:** OSNT-PORT-001

---

### test-cross-tenant-access.sh
**Vulnerability:** VULN-010 - Floating IP Hijacking  
**CVSS Score:** 6.5 (Medium)  
**Purpose:** Tests floating IP association

**STIG Control:** OSNT-FIP-001

---

### test-memcached-tenant-access.sh
**Purpose:** Basic Memcached connectivity test
**STIG Control:** OSCACHE-001

---

### test-memcached-from-tenant-vm.sh
**Purpose:** VM-based Memcached access test

---

## Python Utilities

### memcache_connect.py
**Purpose:** Simple Memcached connection testing

---

### memcached_read_slabs.py
**Purpose:** Slab enumeration and key extraction

---

### memcache_auto.py
**Purpose:** Automated token extraction

---

## Supporting Scripts

### cleanup-memcache-test.sh
**Purpose:** Cleanup test artifacts

---

### demo-vulnerabilities.sh
**Purpose:** Quick vulnerability demonstration

---

## Test Execution Requirements

### Prerequisites
- OpenStack CLI tools
- Python 3.x
- MySQL client: `sudo apt-get install mysql-client`
- Valid credentials (admin-openrc.sh or victim-openrc.sh)

### Execution Instructions
```bash
cd ~/openstack-security-assessment/appendix-c-test-scripts
chmod +x *.sh *.py

# Source credentials
source ~/admin-openrc.sh

# Run tests
./test-memcached-network-exposure.sh
./test-mariadb-network-exposure.sh
```

---

## Test Coverage Matrix

| Vulnerability | Test Script(s) | STIG Control | Result |
|---------------|----------------|--------------|---------|
| VULN-003 | test-cve-2024-32498-qcow2.sh | OSGL-CVE-001 | 126 creds |
| VULN-004 | Manual testing | OSKS-AUTH-001 | Validated |
| VULN-008 | test-neutron-port-isolation.sh | OSNT-PORT-001 | Blocked |
| VULN-010 | test-cross-tenant-access.sh | OSNT-FIP-001 | Blocked |
| VULN-011 | test-memcached-network-exposure.sh | OSCACHE-001 | 20 tokens |
| VULN-012 | test-mariadb-network-exposure.sh | OSDB-NET-001 | 8 DBs |
| VULN-013 | test-cve-2024-32498-attack-chain.sh | OSINFRA-CHAIN-001 | Complete |
| VULN-014 | Manual testing | OSFS-CRED-001 | Fixed |

---

## Validation Results Summary

### Before Remediation
- Vulnerabilities Exploitable: 8/8 (100%)
- Aggregate CVSS: 56.8 (Critical)
- Memcached tokens extracted: 20
- MariaDB databases enumerated: 8
- Credentials stolen: 126

### After Remediation
- Vulnerabilities Blocked: 8/8 (100%)
- Aggregate CVSS: 9.7 (Medium)
- CVSS Reduction: 83%
- Network exposure: Eliminated
- All tests: PASS

---

**Document Version:** 2.0  
**Last Updated:** April 5, 2026  
**Total Scripts:** 25 test scripts + 3 Python utilities  
**Coverage:** 8 vulnerabilities, 100% validation
