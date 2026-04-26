"""Verify shellcode execution: write a marker value to confirm the shellcode runs."""
import subprocess, time, struct, ctypes, os, re

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_RWX = 0x40
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT = 0x1000

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
    return ctypes.cast(val, ctypes.c_void_p).value or 0 if val else 0

def is_writable(p):
    return p in (PAGE_READWRITE, PAGE_WRITECOPY, PAGE_RWX, PAGE_EXECUTE_WRITECOPY)

def main():
    os.system('taskkill /F /IM Lingma.exe 2>nul')
    time.sleep(2)

    print("Starting Lingma...")
    proc = subprocess.Popen([LINGMA, "start"])
    time.sleep(12)

    result_out = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq Lingma.exe', '/FO', 'CSV'], text=True)
    match = re.search(r'"Lingma.exe","(\d+)"', result_out)
    if not match:
        print("Not found!"); proc.kill(); return
    pid = int(match.group(1))
    print(f"PID: {pid}")

    hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hproc:
        print("Failed to open"); proc.kill(); return

    # Find module
    h_snap = kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
    base = None; mod_size = 0
    if h_snap != -1:
        class ME32(ctypes.Structure):
            _fields_ = [
                ('dwSize', ctypes.c_ulong), ('th32ModuleID', ctypes.c_ulong),
                ('th32ProcessID', ctypes.c_ulong), ('GlblcntUsage', ctypes.c_ulong),
                ('ProccntUsage', ctypes.c_ulong), ('modBaseAddr', ctypes.c_void_p),
                ('modBaseSize', ctypes.c_ulong), ('hModule', ctypes.c_void_p),
                ('szModule', ctypes.c_char * 256), ('szExePath', ctypes.c_char * 260),
            ]
        me = ME32(); me.dwSize = ctypes.sizeof(me)
        if kernel32.Module32First(h_snap, ctypes.byref(me)):
            while True:
                if 'lingma.exe' in me.szExePath.decode('utf-8', errors='replace').lower():
                    base = me.modBaseAddr; mod_size = me.modBaseSize; break
                if not kernel32.Module32Next(h_snap, ctypes.byref(me)): break
        kernel32.CloseHandle(h_snap)

    if not base:
        kernel32.CloseHandle(hproc); proc.kill(); return

    getAppSalt_addr = base + 0x882760
    print(f"getAppSalt at: 0x{getAppSalt_addr:x}")

    # Verify JMP is still there from previous run
    current = read_mem(hproc, getAppSalt_addr, 5)
    print(f"Current bytes at getAppSalt: {current.hex(' ')}")
    if current[0] == 0xE9:
        print("JMP is already installed (from previous run)")
    else:
        print("No JMP found, need to install")

    # Find writable region
    mbi = MEMORY_BASIC_INFORMATION(); addr = base
    writable = []
    while addr < base + mod_size:
        r = kernel32.VirtualQueryEx(ctypes.c_void_p(hproc), ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
        if r == 0: break
        if mbi.State == MEM_COMMIT and is_writable(mbi.Protect) and mbi.RegionSize >= 0x200:
            writable.append((to_addr(mbi.BaseAddress), mbi.RegionSize))
        addr += mbi.RegionSize
    writable.sort(key=lambda x: abs(x[0] - getAppSalt_addr))
    best = writable[0]
    sc_addr = best[0] + best[1] - 0x200

    # Simpler shellcode: just write a known marker
    # MARKER at result_addr: 0xDEADBEEF
    # Then call original getAppSalt and return
    result_addr = sc_addr + 0x100

    original_entry = getAppSalt_addr + 5

    shellcode = bytearray()

    # CALL getAppSalt
    call_rel32 = original_entry - (sc_addr + 5)
    if not (-0x80000000 <= call_rel32 < 0x80000000):
        print(f"call_rel32 out of range: 0x{call_rel32:x}")
        kernel32.CloseHandle(hproc); proc.kill(); return
    shellcode += b'\xe8' + struct.pack('<i', call_rel32)

    # Write marker: 0xDEADBEEF at result_addr
    shellcode += b'\xc7\x05'  # mov dword ptr [rip + disp32], imm32
    rip_disp = result_addr - (sc_addr + len(shellcode) + 6)
    shellcode += struct.pack('<i', rip_disp)
    shellcode += struct.pack('<I', 0xDEADBEEF)

    # Also save RAX at result_addr + 8
    shellcode += b'\x48\x89\x05'  # mov [rip+disp], rax
    rip_disp2 = (result_addr + 8) - (sc_addr + len(shellcode) + 7)
    shellcode += struct.pack('<i', rip_disp2)

    # Also save RCX at result_addr + 16
    shellcode += b'\x48\x89\x0d'  # mov [rip+disp], rcx
    rip_disp3 = (result_addr + 16) - (sc_addr + len(shellcode) + 7)
    shellcode += struct.pack('<i', rip_disp3)

    # RET
    shellcode += b'\xc3'

    print(f"\nSimple shellcode ({len(shellcode)} bytes): {bytes(shellcode).hex(' ')}")

    # Write
    write_mem(hproc, sc_addr, bytes(shellcode) + b'\xcc' * (0x100 - len(shellcode)))
    print(f"Shellcode written")

    # Write marker at result_addr before patching (to distinguish old data)
    write_mem(hproc, result_addr, b'\x00' * 32)

    # Patch getAppSalt
    jmp_rel32 = sc_addr - (getAppSalt_addr + 5)
    jmp_bytes = b'\xe9' + struct.pack('<i', jmp_rel32)
    old_prot = ctypes.c_ulong()
    kernel32.VirtualProtectEx(ctypes.c_void_p(hproc), ctypes.c_void_p(getAppSalt_addr),
                               5, PAGE_RWX, ctypes.byref(old_prot))
    write_mem(hproc, getAppSalt_addr, jmp_bytes)
    verify = read_mem(hproc, getAppSalt_addr, 5)
    print(f"JMP: {'OK' if verify == jmp_bytes else 'FAILED'}")

    # Monitor
    print(f"\nMonitoring marker at 0x{result_addr:x} (60s)...")
    for i in range(12):
        time.sleep(5)
        data = read_mem(hproc, result_addr, 32)
        if data:
            marker = struct.unpack('<I', data[0:4])[0]
            rax = struct.unpack('<Q', data[8:16])[0]
            rcx = struct.unpack('<Q', data[16:24])[0]
            print(f"  [{(i+1)*5}s] marker=0x{marker:x} RAX=0x{rax:x} RCX=0x{rcx:x}")

            if marker == 0xDEADBEEF:
                print("  >>> SHELLCODE EXECUTED! Marker found!")
                # Try to read RAX content
                if 0x10000 < rax < 0x7FFFFFFFFFFF:
                    content = read_mem(hproc, rax, 100)
                    if content:
                        try:
                            print(f"  RAX content: {content.decode('utf-8', errors='replace')}")
                        except:
                            print(f"  RAX raw: {content[:30].hex(' ')}")
                break
        else:
            print(f"  [{(i+1)*5}s] Could not read")

    kernel32.CloseHandle(hproc)
    proc.kill()
    print("\nDone!")

if __name__ == '__main__':
    main()
