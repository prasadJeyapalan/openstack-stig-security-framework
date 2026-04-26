# Configuration Files

This directory contains all security-relevant configuration files modified during remediation.

## Directory Structure
```
appendix-d-configuration-files/
|-- APPENDIX-D-CONFIGURATION-FILES.md (Master documentation)
|-- policy-files/
|   |-- glance-policy.yaml (Remediated Glance policy)
|   `-- neutron-policy.yaml (Remediated Neutron policy)
|-- firewall-rules/
|   `-- iptables-rules.txt (All firewall rules)
|-- service-config/
|   `-- glance-api.conf (Glance service configuration)
`-- README-CONFIGS.md (This file)
```

## Usage

These configuration files represent the AFTER remediation state.

To deploy:
1. Copy policy files to /etc/kolla/config/
2. Apply iptables rules
3. Copy service config files
4. Restart affected services

See APPENDIX-D-CONFIGURATION-FILES.md for detailed deployment instructions.
