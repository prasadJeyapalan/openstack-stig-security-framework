import socket, json

def memcache_cmd(cmd):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('192.168.100.11', 11211))
        s.send((cmd + '\r\n').encode())
        response = b''
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            response += chunk
            if b'END\r\n' in response or b'ERROR\r\n' in response:
                break
        s.close()
        return response.decode('utf-8', errors='replace')
    except Exception as e:
        return f"Error: {e}"

# Read items from each slab
slabs = {
    1:  [':1:user_pk_None_restrict'],
    6:  ['0539b531207084e8285102bfb9993317dbd53b55',
         '24c2797f803fc667dab8ab96d920815eae94ffbd',
         '3155eff07a5a85bb96585f8cf6c384f9a12b7af0'],
    7:  ['e1e22e30e477e05cd77e5724a8c6d894ccd7cbf0',
         '7a98265a07df7e6c17607315070bbde8a4b431d4'],
    8:  ['29f650c626be40fc9c8ebc5b0ed92e25c1f4ced0',
         '243ef12b67112bae83165e765ae84e8248bb7c40',
         '7aff4669517128b9705a846b47d95aa656fba89d'],
    9:  ['b1b15d4910f0ba429554ce042d59d1c60e3eeb46',
         '4c06cabfe6e196c320a21362be501d3025354569',
         '1f740088ffd1c831b8447e2381adc0784e34e960']
}

for slab, keys in slabs.items():
    print(f"\n{'='*60}")
    print(f"SLAB {slab} CONTENTS:")
    print('='*60)
    for key in keys:
        result = memcache_cmd(f"get {key}")
        print(f"\nKEY: {key}")
        print(f"VALUE: {result[:600]}")
        print("-"*40)
