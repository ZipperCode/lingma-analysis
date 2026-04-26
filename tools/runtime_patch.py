"""Runtime patch v6: Capture from correct location - Go uses stack-based returns.
After getAppSalt call, return value is at [rsp+0x70] in the caller's frame."""
import subprocess
import time
import struct
import ctypes
import os
import re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT = 0x1000
PAGE_RWX = PAGE_EXECUTE_READWRITE

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', ctypes.c_ulong), ('RegionSize', ctypes.c_size_t),
        ('State', ctypes.c_ulong), ('Protect', ctypes.c_ulong), ('Type', ctypes.c_ulong),
    ]

def read_mem(hproc, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t()
    kernel32.ReadProcessMemory(ctypes.c_void_p(hproc), ctypes.c_void_p(addr),
                                buf, size, ctypes.byref(n))
    return bytes(buf.raw[:n.value])

def write_mem(hproc, addr, data):
    buf = ctypes.create_string_buffer(data)
    n = ctypes.c_size_t()
    return kernel32.WriteProcessMemory(ctypes.c_void_p(hproc), ctypes.c_void_p(addr),
                                        buf, len(data), ctypes.byref(n))

def to_addr(val):
    if val is None:
        return 0
    return ctypes.cast(val, ctypes.c_void_p).value or 0

def is_writable(protect):
    return protect in (PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

def main():
    os.system('taskkill /F /IM Lingma.exe 2>nul')
    time.sleep(2)

    print("Starting Lingma...")
    proc = subprocess.Popen([LINGMA, "start"])
    time.sleep(12)

    result = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq Lingma.exe', '/FO', 'CSV'], text=True)
    match = re.search(r'"Lingma.exe","(\d+)"', result)
    if not match:
        print("Lingma not found!"); proc.kill(); return
    pid = int(match.group(1))
    print(f"PID: {pid}")

    hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hproc:
        print("Failed to open"); proc.kill(); return

    h_snapshot = kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
    base = None; mod_size = 0
    if h_snapshot != -1:
        class MODULEENTRY32(ctypes.Structure):
            _fields_ = [
                ('dwSize', ctypes.c_ulong), ('th32ModuleID', ctypes.c_ulong),
                ('th32ProcessID', ctypes.c_ulong), ('GlblcntUsage', ctypes.c_ulong),
                ('ProccntUsage', ctypes.c_ulong), ('modBaseAddr', ctypes.c_void_p),
                ('modBaseSize', ctypes.c_ulong), ('hModule', ctypes.c_void_p),
                ('szModule', ctypes.c_char * 256), ('szExePath', ctypes.c_char * 260),
            ]
        me = MODULEENTRY32(); me.dwSize = ctypes.sizeof(me)
        if kernel32.Module32First(h_snapshot, ctypes.byref(me)):
            while True:
                if 'lingma.exe' in me.szExePath.decode('utf-8', errors='replace').lower():
                    base = me.modBaseAddr; mod_size = me.modBaseSize
                    print(f"Module: 0x{base:x} - 0x{base + mod_size:x}")
                    break
                if not kernel32.Module32Next(h_snapshot, ctypes.byref(me)):
                    break
        kernel32.CloseHandle(h_snapshot)

    if not base:
        kernel32.CloseHandle(hproc); proc.kill(); return

    getAppSalt_addr = base + 0x882760
    call_addr = base + 0x88114f  # Where getAppSalt is called

    # Find writable region for shellcode
    mbi = MEMORY_BASIC_INFORMATION()
    addr = base
    writable_regions = []
    while addr < base + mod_size:
        r = kernel32.VirtualQueryEx(ctypes.c_void_p(hproc), ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
        if r == 0: break
        if mbi.State == MEM_COMMIT and is_writable(mbi.Protect) and mbi.RegionSize >= 0x200:
            writable_regions.append((to_addr(mbi.BaseAddress), mbi.RegionSize))
        addr += mbi.RegionSize

    writable_regions.sort(key=lambda x: abs(x[0] - getAppSalt_addr))
    best = writable_regions[0]
    shellcode_addr = best[0] + best[1] - 0x200
    # Store return value at shellcode_addr + 0x100
    result_addr = shellcode_addr + 0x100

    print(f"Shellcode at: 0x{shellcode_addr:x}")
    print(f"Result storage at: 0x{result_addr:x}")

    # Build shellcode - capture from stack-based return value location
    # After getAppSalt call, the return value (Go slice) is at [rsp + 0x70]
    # The slice header is: ptr(8) + len(8) + cap(8) = 24 bytes
    # So we read 3 qwords from [rsp + 0x70]

    original_entry = getAppSalt_addr + 5

    shellcode = bytearray()

    # CALL getAppSalt
    call_rel32 = original_entry - (shellcode_addr + 5)
    shellcode += b'\xe8' + struct.pack('<i', call_rel32)

    # pushfq + save all caller-saved regs
    shellcode += b'\x9c\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53'

    # Load result_addr into r11
    shellcode += b'\x49\xbb' + struct.pack('<Q', result_addr)

    # Now read from [rsp + OFFSET] where getAppSalt's return value is stored
    # The return value is at [rsp + 0x70] at the call site AFTER the call returns.
    # But we need to figure out the correct offset from OUR current rsp.
    #
    # At this point in our shellcode:
    #   - We did: CALL (pushes return to original_entry)
    #   - pushfq + 7 pushes = 8 pushes (64 bytes)
    #   - movabs r11 = 10 bytes (no stack change)
    #
    # The return value in the caller's frame is at [caller_rsp + 0x70]
    # Our current rsp = caller_rsp - 8 (from our CALL return address) - 64 (from pushes)
    #                 = caller_rsp - 72
    # So [caller_rsp + 0x70] = [current_rsp + 72 + 0x70] = [current_rsp + 0xE8]

    RET_OFFSET = 0xE8

    # Read 24 bytes of slice header from [rsp + RET_OFFSET]
    # ptr = [rsp + RET_OFFSET]
    # len = [rsp + RET_OFFSET + 8]
    # cap = [rsp + RET_OFFSET + 16]

    # Save ptr
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', RET_OFFSET)  # mov rax, [rsp + offset]
    shellcode += b'\x4c\x89\x03'  # mov [r11], rax

    # Save len
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', RET_OFFSET + 8)  # mov rax, [rsp + offset + 8]
    shellcode += b'\x4c\x89\x43\x08'  # mov [r11+8], rax

    # Save cap
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', RET_OFFSET + 16)  # mov rax, [rsp + offset + 16]
    shellcode += b'\x4c\x89\x43\x10'  # mov [r11+16], rax

    # Also save the actual content (if ptr is valid, try to read the string/bytes it points to)
    # If the return value is []string, each element is at [ptr + i*16]
    # First read the ptr value we just saved
    shellcode += b'\x48\x8b\x03'  # mov rax, [r11]  ; get the ptr we saved

    # Try to read as slice of strings
    # First get the len
    shellcode += b'\x48\x8b\x4b\x08'  # mov rcx, [r11+8]  ; len
    shellcode += b'\x48\x85\xc9'  # test rcx, rcx
    shellcode += b'\x74\x30'  # jz skip_content  ; if len == 0, skip

    # Save first element if len > 0
    # Read first string: ptr = [rax], len = [rax+8]
    shellcode += b'\x48\x8b\x00'  # mov rax, [rax]  ; first element's ptr
    shellcode += b'\x48\x85\xc0'  # test rax, rax
    shellcode += b'\x74\x20'  # jz skip_content

    # Save first string pointer and length at result_addr + 0x20
    shellcode += b'\x4c\x89\x43\x20'  # mov [r11+0x20], rax  ; save first string ptr
    shellcode += b'\x48\x8b\x48\x08'  # mov rcx, [rax+8]  ; first string length
    shellcode += b'\x4c\x89\x4b\x28'  # mov [r11+0x28], rcx  ; save first string len

    # Skip label
    # shellcode += b'...'  ; just continue

    # Restore all
    shellcode += b'\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x9d'

    # RET
    shellcode += b'\xc3'

    print(f"Shellcode ({len(shellcode)} bytes): {bytes(shellcode).hex(' ')}")

    # Write shellcode
    write_mem(hproc, shellcode_addr, bytes(shellcode) + b'\xcc' * (0x100 - len(shellcode)))
    verify = read_mem(hproc, shellcode_addr, len(shellcode))
    print(f"Shellcode: {'OK' if verify == bytes(shellcode) else 'FAILED'}")

    # Zero out result area
    write_mem(hproc, result_addr, b'\x00' * 64)

    # Patch getAppSalt entry
    jmp_rel32 = shellcode_addr - (getAppSalt_addr + 5)
    jmp_bytes = b'\xe9' + struct.pack('<i', jmp_rel32)
    print(f"JMP: 0x{getAppSalt_addr:x} -> 0x{shellcode_addr:x}")

    old_prot = ctypes.c_ulong()
    kernel32.VirtualProtectEx(ctypes.c_void_p(hproc), ctypes.c_void_p(getAppSalt_addr),
                               5, PAGE_RWX, ctypes.byref(old_prot))
    write_mem(hproc, getAppSalt_addr, jmp_bytes)
    verify_jmp = read_mem(hproc, getAppSalt_addr, 5)
    print(f"JMP: {'OK' if verify_jmp == jmp_bytes else 'FAILED'}")

    # Monitor
    print(f"\nMonitoring result at 0x{result_addr:x} (90s)...")
    prev = None
    for i in range(18):
        time.sleep(5)
        data_bytes = read_mem(hproc, result_addr, 64)
        if data_bytes and any(b != 0 for b in data_bytes[:24]):
            sl_ptr = struct.unpack('<Q', data_bytes[0:8])[0]
            sl_len = struct.unpack('<Q', data_bytes[8:16])[0]
            sl_cap = struct.unpack('<Q', data_bytes[16:24])[0]

            changed = " [NEW]" if sl_ptr != (prev or 0) else ""
            print(f"  [{(i+1)*5}s] slice: ptr=0x{sl_ptr:x} len={sl_len} cap={sl_cap}{changed}")

            # Read slice content if valid
            if 0x10000 < sl_ptr < 0x7FFFFFFFFFFF and 0 < sl_len < 20:
                # Read slice elements (each is a string header: ptr+len = 16 bytes)
                for j in range(min(sl_len, 10)):
                    elem_off = j * 16
                    elem_data = read_mem(hproc, sl_ptr + elem_off, 16)
                    if elem_data:
                        ep, el = struct.unpack('<QQ', elem_data)
                        if 0 < el < 500:
                            s = read_mem(hproc, ep, el)
                            if s:
                                try:
                                    print(f"    [{j}] = {s.decode('utf-8', errors='replace')}")
                                except:
                                    print(f"    [{j}] raw = {s.hex(' ')}")

            # Also check the first string we saved separately
            first_ptr = struct.unpack('<Q', data_bytes[0x20:0x28])[0]
            first_len = struct.unpack('<Q', data_bytes[0x28:0x30])[0]
            if 0x10000 < first_ptr < 0x7FFFFFFFFFFF and 0 < first_len < 500:
                s = read_mem(hproc, first_ptr, first_len)
                if s:
                    try:
                        print(f"    First string: {s.decode('utf-8', errors='replace')}")
                    except:
                        print(f"    First string raw: {s.hex(' ')}")

            prev = sl_ptr
        else:
            print(f"  [{(i+1)*5}s] No data")

    kernel32.CloseHandle(hproc)
    proc.kill()
    print("\nDone!")

if __name__ == '__main__':
    main()
