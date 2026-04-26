"""Hook the caller function at 0x880da0 instead of getAppSalt."""
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

    # Hook 0x880da0 (the caller function) instead of getAppSalt
    hook_target = base + 0x880da0
    print(f"Hook target: 0x{hook_target:x}")

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
    writable.sort(key=lambda x: abs(x[0] - hook_target))
    best = writable[0]
    sc_addr = best[0] + best[1] - 0x200
    result_addr = sc_addr + 0x100

    # Shellcode: increment counter + save registers
    shellcode = bytearray()

    # pushfq + save all caller-saved
    shellcode += b'\x9c\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53'

    # Increment call counter at result_addr
    shellcode += b'\x49\xbb' + struct.pack('<Q', result_addr)  # movabs r11, result_addr
    shellcode += b'\xff\x03'  # inc dword [r11]

    # Save RAX, RCX, RDX at result_addr + 0x10
    shellcode += b'\x48\x89\x43\x10'  # mov [r11+0x10], rax
    shellcode += b'\x48\x89\x4b\x18'  # mov [r11+0x18], rcx
    shellcode += b'\x48\x89\x53\x20'  # mov [r11+0x20], rdx

    # Restore all
    shellcode += b'\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x9d'

    # Execute overwritten instruction + JMP back
    # First 5 bytes of 0x880da0: lea r12, [rsp - 0xe8] = 4c 8d a4 24 18 ff ff ff
    shellcode += b'\x4c\x8d\xa4\x24\x18\xff\xff\xff'  # lea r12, [rsp-0xe8]
    # JMP back to hook_target + 5
    jmp_back = (hook_target + 5) - (sc_addr + len(shellcode) + 5)
    shellcode += b'\xe9' + struct.pack('<i', jmp_back)

    print(f"Shellcode ({len(shellcode)} bytes): {bytes(shellcode).hex(' ')}")

    # Write shellcode
    write_mem(hproc, sc_addr, bytes(shellcode) + b'\xcc' * (0x100 - len(shellcode)))
    verify = read_mem(hproc, sc_addr, len(shellcode))
    print(f"Shellcode: {'OK' if verify == bytes(shellcode) else 'FAILED'}")

    # Zero result area
    write_mem(hproc, result_addr, b'\x00' * 0x40)

    # Patch hook target with JMP to shellcode
    jmp_rel32 = sc_addr - (hook_target + 5)
    jmp_bytes = b'\xe9' + struct.pack('<i', jmp_rel32)
    print(f"JMP: 0x{hook_target:x} -> 0x{sc_addr:x}")

    old_prot = ctypes.c_ulong()
    kernel32.VirtualProtectEx(ctypes.c_void_p(hproc), ctypes.c_void_p(hook_target),
                               5, PAGE_RWX, ctypes.byref(old_prot))
    write_mem(hproc, hook_target, jmp_bytes)
    verify_jmp = read_mem(hproc, hook_target, 5)
    print(f"JMP: {'OK' if verify_jmp == jmp_bytes else 'FAILED'}")

    # Monitor
    print(f"\nMonitoring call counter at 0x{result_addr:x} (60s)...")
    prev = 0
    for i in range(12):
        time.sleep(5)
        data = read_mem(hproc, result_addr, 0x40)
        if data:
            counter = struct.unpack('<I', data[0:4])[0]
            rax = struct.unpack('<Q', data[0x10:0x18])[0]
            rcx = struct.unpack('<Q', data[0x18:0x20])[0]
            rdx = struct.unpack('<Q', data[0x20:0x28])[0]

            if counter != prev:
                print(f"  [{(i+1)*5}s] CALLS={counter} RAX=0x{rax:x} RCX=0x{rcx:x} RDX=0x{rdx:x}")
                prev = counter

                # Try to read string at RAX
                if 0x10000 < rax < 0x7FFFFFFFFFFF:
                    content = read_mem(hproc, rax, 100)
                    if content:
                        try:
                            print(f"    RAX string: {content.decode('utf-8', errors='replace')}")
                        except:
                            print(f"    RAX raw: {content[:30].hex(' ')}")
            else:
                print(f"  [{(i+1)*5}s] CALLS={counter} (no change)")
        else:
            print(f"  [{(i+1)*5}s] Could not read")

    kernel32.CloseHandle(hproc)
    proc.kill()
    print("\nDone!")

if __name__ == '__main__':
    main()
