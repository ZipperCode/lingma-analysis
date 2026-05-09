"""Multi-offset monitor: Read multiple stack offsets to find the right one."""
import subprocess, time, struct, ctypes, os, re, json, win32file, win32event, pywintypes

LINGMA = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_RWX = 0x40
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT = 0x1000
MEM_FREE = 0x10000

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

    getAppSalt_addr = base + 0x882760

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

    # We'll use multiple result slots to monitor different offsets
    # result_base[0] = from RAX
    # result_base[1] = from RCX
    # result_base[2] = from RDX
    # result_base[3] = from [rsp+0x70]  <- Go stack return
    # result_base[4] = from [rsp+0x78]
    # result_base[5] = from [rsp+0x80]
    result_base = sc_addr + 0x100

    original_entry = getAppSalt_addr + 5

    shellcode = bytearray()

    # CALL getAppSalt
    call_rel32 = original_entry - (sc_addr + 5)
    shellcode += b'\xe8' + struct.pack('<i', call_rel32)

    # Save all
    shellcode += b'\x9c\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53'

    # After CALL:
    # RAX/RCX/RDX have whatever values the function left
    # [rsp+0x70] (from caller's original RSP) has the Go return value slot

    # Calculate current rsp offset to caller's rsp+0x70:
    # Current rsp points to return address (8 bytes)
    # Caller's original rsp = current_rsp + 8 (return address)
    # Caller's [rsp+0x70] = current_rsp + 8 + 0x70 = current_rsp + 0x78
    # But we pushed 8 regs (64 bytes), so caller's [rsp+0x70] = current_rsp + 64 + 8 + 0x70 = current_rsp + 0xE8

    SLOT_SIZE = 0x20
    rb = result_base  # result base address

    # Load rb into r11
    shellcode += b'\x49\xbb' + struct.pack('<Q', rb)

    # Slot 0: RAX
    shellcode += b'\x58'  # pop rax (get the saved rax value from top of stack)
    shellcode += b'\x50'  # push rax (restore it)
    shellcode += b'\x4c\x89\x03'  # mov [r11], rax

    # Slot 1: RCX (at [rsp+8])
    shellcode += b'\x48\x8b\x4c\x24\x08'  # mov rcx, [rsp+8]
    shellcode += b'\x4c\x89\x4b' + struct.pack('b', SLOT_SIZE)  # mov [r11+0x20], rcx

    # Slot 2: RDX (at [rsp+16])
    shellcode += b'\x48\x8b\x54\x24\x10'  # mov rdx, [rsp+16]
    shellcode += b'\x4c\x89\x53' + struct.pack('b', SLOT_SIZE*2)  # mov [r11+0x40], rdx

    # Slot 3: [rsp+0xE8] - Go return value slot
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', 0xE8)  # mov rax, [rsp+0xE8]
    shellcode += b'\x4c\x89\x43' + struct.pack('b', SLOT_SIZE*3)  # mov [r11+0x60], rax

    # Slot 4: [rsp+0xF0] - next slot
    # 0x80 = 128, need disp32 (ModR/M byte 0x84 24 + disp32)
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', 0xF0)  # mov rax, [rsp+0xF0]
    shellcode += b'\x4c\x89\x44\x24' + struct.pack('<i', 0)  # Can't use modrm, use r11
    # Actually: mov [r11+0x80], rax needs different encoding
    # REX.W=49, ModR/M: [r11+disp32] = 84 9B + disp32
    # Simpler: use movabs to load dest then mov
    shellcode += b'\x49\xba' + struct.pack('<Q', rb + SLOT_SIZE*4)  # movabs rdx, dest
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', 0xF0)  # mov rax, [rsp+0xF0]
    shellcode += b'\x48\x89\x02'  # mov [rdx], rax

    # Slot 5: [rsp+0xF8]
    shellcode += b'\x49\xb9' + struct.pack('<Q', rb + SLOT_SIZE*5)  # movabs rcx, dest
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', 0xF8)  # mov rax, [rsp+0xF8]
    shellcode += b'\x48\x89\x01'  # mov [rcx], rax

    # Also save the raw bytes at [rsp+0xE8] (24 bytes for slice header)
    dest = rb + SLOT_SIZE * 6  # Destination for full slice header
    shellcode += b'\x49\xb9' + struct.pack('<Q', dest)  # movabs rcx, dest

    # Read 24 bytes from [rsp+0xE8] to memory at dest
    # Using rep movsq: rsi = src, rdi = dest, rcx = count
    # src = rsp + 0xE8
    shellcode += b'\x48\x8d\x74\x24\xe8'  # lea rsi, [rsp+0xE8]
    shellcode += b'\x48\x89\xc7'  # mov rdi, rax... wait wrong

    # Simpler: just do 3 movs
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', 0xE8)  # mov rax, [rsp+0xE8]
    shellcode += b'\x48\x89\x01'  # mov [rcx], rax
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', 0xF0)  # mov rax, [rsp+0xF0]
    shellcode += b'\x48\x89\x41\x08'  # mov [rcx+8], rax
    shellcode += b'\x48\x8b\x84\x24' + struct.pack('<i', 0xF8)  # mov rax, [rsp+0xF8]
    shellcode += b'\x48\x89\x41\x10'  # mov [rcx+16], rax

    # Restore all
    shellcode += b'\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x9d'
    shellcode += b'\xc3'

    print(f"Shellcode ({len(shellcode)} bytes)")

    # Write
    write_mem(hproc, sc_addr, bytes(shellcode) + b'\xcc' * (0x100 - len(shellcode)))
    verify = read_mem(hproc, sc_addr, len(shellcode))
    print(f"Shellcode: {'OK' if verify == bytes(shellcode) else 'FAILED'}")

    # Zero result area
    write_mem(hproc, result_base, b'\x00' * 0x100)

    # Patch
    jmp_rel32 = sc_addr - (getAppSalt_addr + 5)
    jmp_bytes = b'\xe9' + struct.pack('<i', jmp_rel32)
    old_prot = ctypes.c_ulong()
    kernel32.VirtualProtectEx(ctypes.c_void_p(hproc), ctypes.c_void_p(getAppSalt_addr),
                               5, PAGE_RWX, ctypes.byref(old_prot))
    write_mem(hproc, getAppSalt_addr, jmp_bytes)
    print(f"JMP: {'OK' if read_mem(hproc, getAppSalt_addr, 5) == jmp_bytes else 'FAILED'}")

    # Now trigger getAppSalt via pipe
    info_path = 'C:/Users/Zipper/.lingma/.info.json'
    try:
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
        time.sleep(2)
        read_resp(handle)

        send_rpc(handle, "textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 0, "character": 0}
        }, 2)
        time.sleep(5)
        read_resp(handle, 5000)

        send_rpc(handle, "chat/ask", {
            "sessionId": "t1", "chatId": "c1",
            "message": "What is 2+2?", "stream": False
        }, 3)
        time.sleep(10)
        read_resp(handle, 10000)

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    # Monitor all slots
    print(f"\nMonitoring {90}s...")
    slot_names = ['RAX', 'RCX', 'RDX', '[rsp+0xE8]', '[rsp+0xF0]', '[rsp+0xF8]', 'Slice Header']
    prev = [None] * 7

    for i in range(18):
        time.sleep(5)
        data = read_mem(hproc, result_base, 0x100)
        if data and any(b != 0 for b in data[:0x20]):
            changed_any = False
            for s in range(7):
                val = struct.unpack('<Q', data[s*0x20:(s+1)*0x20][:8])[0]
                if val != (prev[s] or 0) and val != 0:
                    changed_any = True
                    prev[s] = val
                    print(f"  [{(i+1)*5}s] Slot {s} ({slot_names[s]}) = 0x{val:x}")

                    # If this looks like a valid pointer
                    if 0x10000 < val < 0x7FFFFFFFFFFF:
                        content = read_mem(hproc, val, 100)
                        if content:
                            try:
                                print(f"    String: {content.decode('utf-8', errors='replace')}")
                            except:
                                print(f"    Raw: {content[:30].hex(' ')}")

                        # Try as slice header
                        sh = read_mem(hproc, val, 24)
                        if sh:
                            sp, sl, sc = struct.unpack('<QQQ', sh)
                            if 0x10000 < sp < 0x7FFFFFFFFFFF and 0 < sl < 50:
                                print(f"    Slice: ptr=0x{sp:x} len={sl} cap={sc}")
                                for j in range(min(sl, 5)):
                                    elem = read_mem(hproc, sp + j*16, 16)
                                    if elem:
                                        ep, el = struct.unpack('<QQ', elem)
                                        if 0 < el < 500:
                                            s_content = read_mem(hproc, ep, el)
                                            if s_content:
                                                print(f"      [{j}] = {s_content.decode('utf-8', errors='replace')}")
                elif val != 0 and prev[s] is None:
                    prev[s] = val
            if changed_any:
                print()
        else:
            print(f"  [{(i+1)*5}s] No data")

    kernel32.CloseHandle(hproc)
    proc.kill()
    print("\nDone!")

if __name__ == '__main__':
    main()
