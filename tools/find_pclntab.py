"""
直接搜索 Go pclntab 魔法字节来定位函数表
Go 1.21+ 使用版本字符串如 "go1.23.0" 作为 pclntab header 开始
"""
import struct
import mmap

BINARY_PATH = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

def main():
    with open(BINARY_PATH, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    # Step 1: Search for Go version string to find pclntab header
    # Go 1.21+ uses version string at start of pclntab
    version_strings = [b'go1.23', b'go1.22', b'go1.21', b'go1.20', b'go1.19']

    for ver in version_strings:
        pos = mm.find(ver)
        if pos >= 0:
            print(f"Found {ver} at file offset 0x{pos:x}")
            # Check if this is a pclntab header
            # For Go 1.20+, pclntab starts with version string followed by
            # 1 byte flags, then 4 bytes (nfunc), 8 bytes (functions)
            print(f"  Context: {mm[pos-10:pos+50].hex()}")
            print(f"  ASCII: {mm[pos:pos+50]}")

            # For Go 1.21+, header is:
            # 8 bytes: version string "go1.21\0\0" or similar
            # 1 byte: flags
            # 4 bytes: nfunc (number of functions)
            # 8 bytes: functions pointer

            # Try reading after version string
            header_start = pos
            # The version string might be null-padded to 8 bytes
            after_version = pos + 8
            try:
                flags = mm[after_version]
                nfunc = struct.unpack('<I', mm[after_version+1:after_version+5])[0]
                func_ptr = struct.unpack('<Q', mm[after_version+5:after_version+13])[0]
                print(f"  If pclntab header: flags=0x{flags:x}, nfunc={nfunc}, func_ptr=0x{func_ptr:x}")

                if 0 < nfunc < 200000:  # Reasonable function count
                    print(f"  *** LIKELY VALID pclntab header! ***")
            except:
                print(f"  Could not parse as Go 1.21+ header")
            break

    # Step 2: Alternative - search for pclntab magic bytes
    # Go 1.2 and earlier: 0xFFFFFFFB (little-endian: FB FF FF FF)
    for magic in [b'\xFB\xFF\xFF\xFF', b'\xFA\xFF\xFF\xFF']:
        pos = mm.find(magic)
        if pos >= 0:
            print(f"\nFound pclntab magic {magic.hex()} at file offset 0x{pos:x}")
            nfunc = struct.unpack('<I', mm[pos+4:pos+8])[0]
            print(f"  nfunc={nfunc}")
            break

    # Step 3: Search for getAppSalt in all strings
    # First, let's find ALL strings that contain "getAppSalt"
    print("\n\nSearching for getAppSalt in binary...")
    search_str = b'getAppSalt'
    pos = 0
    while True:
        idx = mm.find(search_str, pos)
        if idx < 0:
            break
        context = mm[idx-20:idx+50]
        context_str = ''.join(chr(c) if 32 <= c < 127 else '.' for c in context)
        print(f"  Found at offset 0x{idx:x}")
        print(f"  Context: ...{context_str}...")

        # Check what section this is in
        # We need to figure out if this is in .rdata (function name) or .text (code)
        # or .rodata (string constant)
        pos = idx + 1

    # Step 4: Let's also search for "AppSalt" or "Salt" to find related strings
    print("\n\nSearching for 'Salt' in binary...")
    pos = 0
    while True:
        idx = mm.find(b'Salt', pos)
        if idx < 0:
            break
        # Get surrounding printable string
        start = idx
        while start > 0 and 32 <= mm[start-1] < 127:
            start -= 1
        end = idx + 4
        while end < len(mm) and 32 <= mm[end] < 127:
            end += 1
        s = mm[start:end].decode('ascii', errors='replace')
        print(f"  0x{idx:x}: {s}")
        pos = idx + 1

    mm.close()

if __name__ == '__main__':
    main()
