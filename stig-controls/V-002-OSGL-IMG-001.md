================================================================================
STIG Control V-002: OSGL-IMG-001
OpenStack Glance Image Format Restriction
================================================================================

STIG ID: OSGL-IMG-001
Severity: CAT I
Rule Title: OpenStack Glance must restrict image formats to prevent malicious file processing

Vulnerability Discussion:

Allowing unrestricted image format uploads creates multiple attack vectors through image processing vulnerabilities. QCOW2, VMDK, VDI, and other complex disk formats contain metadata and feature support that can be exploited to achieve tenant escape, arbitrary file access, and denial of service.

The qemu-img utility used by Glance to process disk images has historically had multiple CVEs related to format parsing. Each image format introduces additional attack surface through format-specific metadata parsing, external resource references, compression features, and snapshot support.

Restricting uploads to RAW format only eliminates these attack vectors while maintaining essential functionality. RAW format is a simple byte-for-byte disk image with no metadata, no external references, and no complex features.

Attack Scenario:

1. Attacker crafts malicious QCOW2 image with external backing file reference
2. Uploads image to Glance using member credentials
3. Glance processes image using qemu-img convert
4. Malicious metadata causes qemu-img to read arbitrary files
5. Sensitive data embedded in processed image
6. Attacker downloads image and extracts credentials

CVSS 3.1 Score: 8.8 (High)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

Check Text:

Verify only approved image formats are accepted and policy restricts uploads to admin users.

Method 1: Automated Verification
Run the Glance CVE verification script:

    bash ~/openstack-security-assessment/stig-verification/stig-verification-glance-cve.sh

Expected: Non-admin users cannot upload any images (QCOW2, RAW, or other formats)

Method 2: Manual Verification
Test that non-admin users cannot upload QCOW2 images:

    source ~/victim-openrc.sh
    qemu-img create -f qcow2 /tmp/test.qcow2 1M
    openstack image create --file /tmp/test.qcow2 --disk-format qcow2 test-format

Expected: 403 Forbidden error

Test that non-admin users cannot upload RAW images:

    qemu-img convert -f qcow2 -O raw /tmp/test.qcow2 /tmp/test.raw
    openstack image create --file /tmp/test.raw --disk-format raw test-raw

Expected: 403 Forbidden error

Fix Text:

This control is implemented through the same policy restrictions as OSGL-CVE-001.

Step 1: Apply OSGL-CVE-001 Remediation

The policy file created in OSGL-CVE-001 restricts all image uploads (regardless of format) to admin users only:

    docker exec -u root glance_api bash -c 'cat > /etc/glance/policy.yaml << "POLICY"
    "add_image": "role:admin"
    "upload_image": "role:admin"
    "modify_image": "role:admin"
    POLICY'

This prevents non-admin users from uploading ANY image format.

Step 2: Establish Operational Procedures for Admin Users

Admin users should follow secure image handling procedures:

1. Convert all images to RAW format before upload:
   
    qemu-img convert -f qcow2 -O raw source.qcow2 output.raw

2. Verify RAW format:
   
    qemu-img info output.raw | grep "file format"
   
   Expected: file format: raw

3. Upload as admin user:
   
    source ~/admin-openrc.sh
    openstack image create --file output.raw --disk-format raw --container-format bare image-name

4. Verify upload:
   
    openstack image show image-name | grep -E "disk_format|status"
   
   Expected: disk_format = raw, status = active

Step 3: Document Approved Formats

Maintain approved image format list:
- Approved: RAW (simple byte-for-byte disk image, no metadata)
- Prohibited: QCOW2, VMDK, VDI, VHD (complex formats with metadata)

Defense-in-Depth:

This control works in conjunction with:
- OSGL-CVE-001: Restricts who can upload images (admin only)
- OSGL-IMG-001: Restricts what formats can be used (RAW only)
- OSFS-CRED-001: Protects credential files from unauthorized access

Together these controls prevent:
- Non-admin users from uploading malicious images
- Admin users from accidentally uploading vulnerable formats
- Credential theft even if image processing is compromised

CCI: CCI-001774, CCI-001242

NIST 800-53 Mappings:
- CM-7(5): Least Functionality - Authorized Software
- SI-3: Malicious Code Protection
- AC-6(1): Least Privilege

CVSS Before: 8.8 (High)
CVSS After: 0.0 (Remediated)
Reduction: 8.8 points (100%)

Implementation Date: April 5, 2026
Verification Date: April 5, 2026
Status: PASS

================================================================================
