import socket

def memcache_cmd(cmd):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('192.168.100.11', 11211))
        s.send((cmd + '\r\n').encode())
        response = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if b'END\r\n' in response or b'ERROR\r\n' in response:
                break
        s.close()
        return response.decode('utf-8', errors='replace')
    except Exception as e:
        return f"Error: {e}"

print("=== STEP 1: Dump keys from slab 1 ===")
dump = memcache_cmd("stats cachedump 1 100")
print(dump)

print("=== STEP 2: Try to read any keys found ===")
# Parse keys from dump
for line in dump.split('\n'):
    if line.startswith('ITEM'):
        key = line.split(' ')[1]
        print(f"\nReading key: {key}")
        value = memcache_cmd(f"get {key}")
        print(value[:500])

print("=== STEP 3: Check all slabs for data ===")
for slab in range(1, 10):
    result = memcache_cmd(f"stats cachedump {slab} 10")
    if 'ITEM' in result:
        print(f"Slab {slab} has items:")
        print(result)
