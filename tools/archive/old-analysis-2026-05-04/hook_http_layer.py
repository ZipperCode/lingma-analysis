"""Hook net/http.(*Client).do to intercept ALL HTTP requests."""
import subprocess, time, struct, ctypes, os, re, json, win32file, win32event, pywintypes

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

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params: body["params"] = params
    if msg_id is not None: body["id"] = msg_id
    content = json.dumps(body)
    header = "Content-Length: {}\r\n\r\n".format(len(content))
    win32file.WriteFile(handle, (header + content).encode('utf-8'))

def read_resp(handle, timeout_ms=3000):
    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
    try:
        err, data = win32file.ReadFile(handle, 65536, overlapped)
        if err == 997:
            result = win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms)
            if result == win32event.WAIT_OBJECT_0:
                data = bytes(overlapped.GetOverlappedResult())
            else:
                return None
        else:
            data = bytes(data)
    except:
        return None
    if data:
        text = data.decode('utf-8', errors='replace')
        if '\r\n\r\n' in text:
            _, body = text.split('\r\n\r\n', 1)
            return body[:500]
    return None

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

    # Find writable region
    mbi = MEMORY_BASIC_INFORMATION(); addr = base
    writable = []
    while addr < base + mod_size:
        r = kernel32.VirtualQueryEx(ctypes.c_void_p(hproc), ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
        if r == 0: break
        if mbi.State == MEM_COMMIT and is_writable(mbi.Protect) and mbi.RegionSize >= 0x400:
            writable.append((to_addr(mbi.BaseAddress), mbi.RegionSize))
        addr += mbi.RegionSize

    if not writable:
        print("No writable region found"); kernel32.CloseHandle(hproc); proc.kill(); return

    writable.sort(key=lambda x: x[1], reverse=True)  # Sort by size, largest first
    best = writable[0]
    sc_addr = best[0] + best[1] - 0x400
    result_area = sc_addr + 0x200

    print(f"Writable region: 0x{best[0]:x} size=0x{best[1]:x}")
    print(f"Shellcode at: 0x{sc_addr:x}")
    print(f"Result area: 0x{result_area:x}")

    # Simple shellcode: write marker, save first arg, return to caller
    # This hooks the FIRST function in .text (runtime.rt0_go or similar)
    # Actually, let's hook something in the LSP startup path

    # For now, let's just verify our patching works by hooking a startup function
    # runtime.main is the Go program entry point

    # Actually, let's hook the pipe handler instead
    # Let me try a different approach: hook a high-frequency function that we KNOW is called

    # The function at RVA 0x102e0 (first function in getAppSalt's value loading chain)
    # Let's check if it's called during startup

    hook_target = base + 0x102e0  # Some internal function
    print(f"\nHook target: 0x{hook_target:x}")

    # Read original bytes
    orig = read_mem(hproc, hook_target, 16)
    print(f"Original bytes: {orig.hex(' ')}")

    # Shellcode: increment counter, save RDI (first arg)
    shellcode = bytearray()

    # pushfq + save all caller-saved
    shellcode += b'\x9c\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53'

    # Increment counter
    shellcode += b'\x49\xbb' + struct.pack('<Q', result_area)
    shellcode += b'\xff\x03'  # inc dword [r11]

    # Save RDI (Go often uses this for method receivers)
    shellcode += b'\x4c\x89\x7b\x08'  # mov [r11+8], rdi
    shellcode += b'\x4c\x89\x43\x10'  # mov [r11+0x10], rax
    shellcode += b'\x4c\x89\x4b\x18'  # mov [r11+0x18], rcx

    # Restore all
    shellcode += b'\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x9d'

    # Execute original instructions (first 5 bytes) + JMP back
    shellcode += orig[:5]
    jmp_back = (hook_target + 5) - (sc_addr + len(shellcode) + 5)
    shellcode += b'\xe9' + struct.pack('<i', jmp_back)

    print(f"Shellcode ({len(shellcode)} bytes)")

    # Write shellcode
    write_mem(hproc, sc_addr, bytes(shellcode) + b'\xcc' * (0x200 - len(shellcode)))

    # Zero result area
    write_mem(hproc, result_area, b'\x00' * 0x100)

    # Patch
    jmp_rel32 = sc_addr - (hook_target + 5)
    jmp_bytes = b'\xe9' + struct.pack('<i', jmp_rel32)

    old_prot = ctypes.c_ulong()
    kernel32.VirtualProtectEx(ctypes.c_void_p(hproc), ctypes.c_void_p(hook_target),
                               5, PAGE_RWX, ctypes.byref(old_prot))
    write_mem(hproc, hook_target, jmp_bytes)
    verify = read_mem(hproc, hook_target, 5)
    print(f"JMP: {'OK' if verify == jmp_bytes else 'FAILED'}")

    # Trigger RPC calls
    print("\nTriggering RPC calls...")
    try:
        info_path = 'C:/Users/Zipper/.lingma/.info.json'
        with open(info_path, 'r') as f:
            info = json.load(f)
        pipe_path = info.get('ipcServerPath')
        print(f"Pipe: {pipe_path}")

        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED, None
        )
        print("Connected!")

        send_rpc(handle, "initialize", {
            "processId": 12345, "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US", "rootPath": "C:/test"
        }, 1)
        time.sleep(3)
        read_resp(handle)

        send_rpc(handle, "textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 0, "character": 0}
        }, 2)
        time.sleep(5)
        read_resp(handle, 5000)

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    # Monitor
    print(f"\nMonitoring (30s)...")
    prev = 0
    for i in range(6):
        time.sleep(5)
        data = read_mem(hproc, result_area, 0x20)
        if data:
            counter = struct.unpack('<I', data[0:4])[0]
            rdi = struct.unpack('<Q', data[8:16])[0]
            rax = struct.unpack('<Q', data[16:24])[0]
            rcx = struct.unpack('<Q', data[24:32])[0]

            if counter != prev:
                print(f"  [{(i+1)*5}s] CALLS={counter} RDI=0x{rdi:x} RAX=0x{rax:x} RCX=0x{rcx:x}")
                prev = counter

                # Try reading string at RAX
                if 0x10000 < rax < 0x7FFFFFFFFFFF:
                    content = read_mem(hproc, rax, 100)
                    if content:
                        try:
                            print(f"    RAX: {content.decode('utf-8', errors='replace')}")
                        except:
                            print(f"    RAX raw: {content[:30].hex(' ')}")
            else:
                print(f"  [{(i+1)*5}s] CALLS={counter} (no change)")

    kernel32.CloseHandle(hproc)
    proc.kill()
    print("\nDone!")

if __name__ == '__main__':
    main()
