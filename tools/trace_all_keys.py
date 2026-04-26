import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import re

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def parse_sections(pe_data):
    e_lfanew = struct.unpack('<I', pe_data[60:64])[0]
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack('<H', pe_data[coff_offset+2:coff_offset+4])[0]
    opt_header_size = struct.unpack('<H', pe_data[coff_offset+16:coff_offset+18])[0]
    section_offset = coff_offset + 20 + opt_header_size

    sections = []
    for i in range(num_sections):
        sec = pe_data[section_offset + i*40 : section_offset + (i+1)*40]
        sections.append({
            'name': sec[0:8].rstrip(b'\x00').decode('ascii', errors='replace'),
            'virtual_address': struct.unpack('<I', sec[12:16])[0],
            'virtual_size': struct.unpack('<I', sec[8:12])[0],
            'raw_offset': struct.unpack('<I', sec[20:24])[0],
            'raw_size': struct.unpack('<I', sec[16:20])[0],
        })
    return sections

def va_to_file_offset(sections, va):
    for sec in sections:
        va_start = sec['virtual_address']
        va_end = va_start + max(sec['virtual_size'], sec['raw_size'])
        if va_start <= va < va_end:
            return sec['raw_offset'] + (va - va_start)
    return None

with open(BINARY_PATH, 'rb') as f:
    pe_data = f.read()

sections = parse_sections(pe_data)
md = Cs(CS_ARCH_X86, CS_MODE_64)

# For each caller, find the key (2nd argument = string passed to RDI)
# The AesEncryptWithBase64 function signature is:
# func AesEncryptWithBase64(plaintext string, key string) string
#
# In Go register calling convention:
# arg1 (string): data ptr in RAX, len in RBX (or similar)
# arg2 (string): data ptr in RCX, len in RDX (or similar)

# Actually let me re-examine the function prologue more carefully
# to understand the argument layout

print("=== Detailed register flow for AesEncryptWithBase64 ===")
print("""
At function entry (0x455da0), the Go register convention uses:
- RAX: 1st arg (string header ptr)
- RBX: 1st arg (string length)
- RCX: 2nd arg (string header ptr)
- RDX: 2nd arg (string length)
- RDI: might be 3rd arg

The function saves:
- [rsp+0xa0] = RAX (plaintext string header)
- [rsp+0xb8] = RDI (some string - might be the key!)
- [rsp+0xb0] = RCX (another string)

Then it converts RAX to []byte and calls aes.NewCipher.
Then converts [rsp+0xb0] (= RCX original) to []byte.
So the key comes from RCX, not RDI.

Wait, let me re-examine:
  0x455dba: mov [rsp+0xa0], rax    # Save RAX (arg1 = plaintext)
  0x455dc2: mov [rsp+0xb8], rdi    # Save RDI
  0x455dca: mov [rsp+0xb0], rcx    # Save RCX

  0x455dd2: mov rdx, rax           # RDX = RAX (string)
  0x455dd7: mov rsi, rbx           # RSI = RBX (string length)
  0x455dda: mov rbx, rdx           # RBX = string ptr
  0x455ddd: mov rcx, rsi           # RCX = string length
  0x455de0: call 0x5bfe0           # stringToBytes(string)

  After this call:
  RAX = []byte header
  RBX = data pointer
  RCX = length

  Then:
  0x455df6: mov rbx, [rsp+0xb0]    # RBX = original RCX (key string)
  0x455dfe: mov rcx, [rsp+0xb8]    # RCX = original RDI
  0x455e06: call 0x5bfe0           # stringToBytes(key string)

  After this: RAX = []byte (key), RBX/RCX = data/len

  0x455e1a: call 0x1857e0          # aes.NewCipher(key_bytes)

So:
- arg1 (via RAX): plaintext string
- arg2 (via RCX, saved to [rsp+0xb0]): key string

But where does RDI come from? It's also saved to [rsp+0xb8].
Looking at the callers:
""")

# Caller 4: mov rcx, [rip+...] / mov rdi, [rip+...] / call 0x455da0
# Here RCX is loaded with a pointer, RDI is loaded with another pointer
# RCX likely = key string header, RDI likely = plaintext string header

print("Caller 4 register setup:")
print("  RCX = [rip + 0x54b5e71] -> key string header")
print("  RDI = [rip + 0x54b5e72] -> plaintext string header")

# Let's trace back further to find which callers are used for which endpoints
# The caller functions at 0x88xxxx and 0x89xxxx are in the cosy/encrypt package
# The callers at 0xafxxxx and 0xb9xxxx might be HTTP client code

# Let's look for the function that calls AesEncryptWithBase64 from the HTTP layer
# Specifically for the heartbeat endpoint

print("\n\n=== Searching for heartbeat/agent-related encryption callers ===")
# Look for callers that are in HTTP-related code
rdata_section = sections[1]
rdata_raw = pe_data[rdata_section['raw_offset']:rdata_section['raw_offset'] + rdata_section['raw_size']]

# Search for function names related to heartbeat or agent encryption
for pattern in [b'heartbeat', b'HeartBeat', b'agent', b'chat', b'ask', b'remoting', b'api']:
    for m in re.finditer(pattern, rdata_raw):
        start = max(0, m.start() - 20)
        end = min(len(rdata_raw), m.end() + 100)
        context = rdata_raw[start:end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        va = rdata_section['virtual_address'] + m.start()
        # Only show full function names (with package path)
        if b'cosy' in context.lower() or b'/' in context:
            print(f"  0x{va:x}: {printable[:180]}")

# Now let's look at the callers in the 0x88xxxx and 0x89xxxx range
# These are the ones that call AesEncryptWithBase64 with `mov edi, 0x10`
# Let's find the function names for these callers

print("\n\n=== Finding function names for callers ===")
# The callers are at:
# 0x88eea6 - in some encrypt-related function
# 0x892305 - in another encrypt-related function
# 0x8926e2 - yet another
# 0xaf33a6 - HTTP-level encryption
# 0xb96f68 - HTTP-level encryption

# Look for function names in the pclntab for these ranges
# Function names appear as fully-qualified paths like:
# code.alibaba-inc.com/cosy/encrypt.AesEncryptWithBase64

for caller_range in [(0x88e000, 0x890000, "encrypt package caller 1"),
                      (0x892000, 0x893000, "encrypt package caller 2"),
                      (0x892500, 0x892800, "encrypt package caller 3"),
                      (0xaf3000, 0xaf4000, "HTTP caller 1"),
                      (0xb96f00, 0xb97100, "HTTP caller 2")]:
    start, end, desc = caller_range
    # Search for this VA range in the pclntab
    # The pclntab maps PC values to function names
    # Function names in the binary contain the VA ranges

    # Instead, search for the function name by looking for patterns
    # that include "encrypt" near the caller's address
    for m in re.finditer(b'encrypt', rdata_raw):
        # Get surrounding context
        start_ctx = max(0, m.start() - 5)
        end_ctx = min(len(rdata_raw), m.end() + 300)
        context = rdata_raw[start_ctx:end_ctx]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)

        # Look for function names that include AesEncrypt or the caller's VA
        if any(x in printable for x in ['AesEncrypt', 'EncryptMessage', 'EncryptBody', 'encryptPayload']):
            va = rdata_section['virtual_address'] + m.start()
            print(f"  [{desc}] 0x{va:x}: {printable[:300]}")
