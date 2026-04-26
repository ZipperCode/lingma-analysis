"""
Test patched Lingma.exe - simplified version that just monitors memory.
"""
import subprocess
import time
import struct
import ctypes
import ctypes.wintypes
import json
import win32file
import win32event
import pywintypes
import os
import re

LINGMA_PATCHED = 'D:/Project/lingma/tools/Lingma_patched.exe'
LINGMA_ORIGINAL = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

# Where results are stored (RVA in .data section)
RESULT_RVA = 0x5c3e000

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF

def read_process_memory(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = kernel32.ReadProcessMemory(
        ctypes.c_void_p(handle),
        ctypes.c_void_p(addr),
        buf, size,
        ctypes.byref(bytes_read)
    )
    if not success:
        return None
    return bytes(buf.raw[:bytes_read.value])

def send_rpc(handle, method, params=None, msg_id=None):
    body = {"jsonrpc": "2.0", "method": method}
    if params:
        body["params"] = params
    if msg_id is not None:
        body["id"] = msg_id
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
    # Kill existing
    os.system('taskkill /F /IM Lingma.exe 2>nul')
    time.sleep(3)

    # Start patched
    print("Starting PATCHED Lingma...")
    proc = subprocess.Popen([LINGMA_PATCHED, "start"])
    time.sleep(12)

    # Find PID
    result = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq Lingma.exe', '/FO', 'CSV'], text=True)
    match = re.search(r'"Lingma.exe","(\d+)"', result)
    if not match:
        print("Lingma not running!")
        proc.kill()
        return
    pid = int(match.group(1))
    print(f"PID: {pid}")

    # Open process
    hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hproc:
        print(f"Failed to open process (error {ctypes.get_last_error()})")
        proc.kill()
        return

    # Find module base
    h_snapshot = kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
    base = None
    if h_snapshot != -1:
        class MODULEENTRY32(ctypes.Structure):
            _fields_ = [
                ('dwSize', ctypes.c_ulong),
                ('th32ModuleID', ctypes.c_ulong),
                ('th32ProcessID', ctypes.c_ulong),
                ('GlblcntUsage', ctypes.c_ulong),
                ('ProccntUsage', ctypes.c_ulong),
                ('modBaseAddr', ctypes.c_void_p),
                ('modBaseSize', ctypes.c_ulong),
                ('hModule', ctypes.c_void_p),
                ('szModule', ctypes.c_char * 256),
                ('szExePath', ctypes.c_char * 260),
            ]
        me = MODULEENTRY32()
        me.dwSize = ctypes.sizeof(me)
        if kernel32.Module32First(h_snapshot, ctypes.byref(me)):
            while True:
                path = me.szExePath.decode('utf-8', errors='replace').lower()
                if 'lingma.exe' in path:
                    base = me.modBaseAddr
                    print(f"Module base: 0x{base:x}")
                    break
                if not kernel32.Module32Next(h_snapshot, ctypes.byref(me)):
                    break
        kernel32.CloseHandle(h_snapshot)

    if not base:
        print("Could not find module base!")
        kernel32.CloseHandle(hproc)
        proc.kill()
        return

    # Calculate absolute address
    result_addr = base + RESULT_RVA
    print(f"Result storage at: 0x{result_addr:x}")

    # Read initial values
    def read_result():
        rax_bytes = read_process_memory(hproc, result_addr, 8)
        rcx_bytes = read_process_memory(hproc, result_addr + 8, 8)
        rdx_bytes = read_process_memory(hproc, result_addr + 16, 8)
        if rax_bytes:
            return struct.unpack('<Q', rax_bytes)[0], struct.unpack('<Q', rcx_bytes)[0], struct.unpack('<Q', rdx_bytes)[0]
        return None, None, None

    rax, rcx, rdx = read_result()
    print(f"Initial: RAX=0x{rax:x} RCX={rcx} RDX={rdx}")

    # Try to trigger getAppSalt via pipe
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
        print("Connected to pipe!")

        # Initialize
        print("\nSending initialize...")
        send_rpc(handle, "initialize", {
            "processId": 12345,
            "clientInfo": {"name": "vscode", "version": "1.95.0"},
            "locale": "en-US", "rootPath": "C:/test"
        }, 1)
        time.sleep(2)

        # Completion
        print("Sending textDocument/completion...")
        send_rpc(handle, "textDocument/completion", {
            "textDocument": {"uri": "file:///C:/test/hello.py"},
            "position": {"line": 0, "character": 0}
        }, 2)
        time.sleep(5)

        # Chat
        print("Sending chat/ask...")
        send_rpc(handle, "chat/ask", {
            "sessionId": "t1", "chatId": "c1",
            "message": "hello", "stream": False
        }, 3)
        time.sleep(10)

        # Check results
        rax, rcx, rdx = read_result()
        print(f"\nAfter RPC calls: RAX=0x{rax:x} RCX={rcx} RDX={rdx}")

        if rax and rax > 0x10000 and rax < 0x7FFFFFFFFFFF:
            print(f"  RAX looks like a valid pointer!")
            # Try to read the content
            if rcx > 0 and rcx < 10000:
                content = read_process_memory(hproc, rax, min(rcx, 200))
                if content:
                    print(f"  Content: {content}")
            # Try reading as slice header
            try:
                slice_bytes = read_process_memory(hproc, rax, 24)
                if slice_bytes:
                    ptr, length, cap = struct.unpack('<QQQ', slice_bytes)
                    print(f"  As slice: ptr=0x{ptr:x} len={length} cap={cap}")
                    if length > 0 and length < 20:
                        for i in range(length):
                            elem_bytes = read_process_memory(hproc, ptr + i * 16, 16)
                            if elem_bytes:
                                ep, el = struct.unpack('<QQ', elem_bytes)
                                if el > 0 and el < 500:
                                    s = read_process_memory(hproc, ep, el)
                                    if s:
                                        print(f"    [{i}] = {s.decode('utf-8', errors='replace')}")
            except:
                pass

        win32file.CloseHandle(handle)
    except Exception as e:
        print(f"Pipe error: {e}")

    # Wait and monitor
    print("\nMonitoring for 30 seconds...")
    prev_rax = rax
    for i in range(6):
        time.sleep(5)
        rax, rcx, rdx = read_result()
        changed = " [CHANGED]" if rax != prev_rax else ""
        print(f"  [{(i+1)*5}s] RAX=0x{rax:x} RCX={rcx} RDX={rdx}{changed}")
        if rax != prev_rax:
            prev_rax = rax

    kernel32.CloseHandle(hproc)
    proc.kill()
    print("\nDone!")

if __name__ == '__main__':
    main()
