"""
Test the patched Lingma.exe binary and read getAppSalt return values.
Uses ReadProcessMemory to read the captured values from .data section.
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

LINGMA_PATCHED = 'D:/Project/lingma/tools/Lingma_patched.exe'
LINGMA_ORIGINAL = 'C:/Users/Zipper/.lingma/bin/2.11.1/x86_64_windows/Lingma.exe'

# Where we store the result (RVA in .data section)
RESULT_RVA = 0x5c3e000  # RAX (ptr to return value)
RESULT_LEN_RVA = 0x5c3e008  # RCX (length)
RESULT_CAP_RVA = 0x5c3e010  # RDX (cap)

# Windows API for ReadProcessMemory
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

def read_process_memory(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = kernel32.ReadProcessMemory(
        ctypes.c_void_p(handle),
        ctypes.c_void_p(addr),
        buf,
        size,
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

def find_process(pid):
    """Get process handle via OpenProcess"""
    PROCESS_ALL_ACCESS = 0x1F0FFF
    return kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

def main():
    # Kill existing
    os.system('taskkill /F /IM Lingma.exe 2>nul')
    time.sleep(2)

    # Use original for pipe info first
    print("Starting ORIGINAL Lingma to get pipe info...")
    proc_orig = subprocess.Popen([LINGMA_ORIGINAL, "start"])
    time.sleep(10)

    # Get pipe path
    info_path = 'C:/Users/Zipper/.lingma/.info.json'
    try:
        with open(info_path, 'r') as f:
            info = json.load(f)
        pipe_path = info.get('ipcServerPath')
        print(f"Pipe: {pipe_path}")
    except Exception as e:
        print(f"Failed to get pipe info: {e}")
        pipe_path = None

    # Kill original
    proc_orig.kill()
    proc_orig.wait()
    time.sleep(2)

    # Start patched
    print("\nStarting PATCHED Lingma...")
    proc = subprocess.Popen([LINGMA_PATCHED, "start"])
    time.sleep(10)

    # Find PID
    result = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq Lingma.exe', '/FO', 'CSV'], text=True)
    print(f"Process list: {result}")

    import re
    match = re.search(r'"Lingma.exe","(\d+)"', result)
    if match:
        pid = int(match.group(1))
        print(f"PID: {pid}")
    else:
        print("Could not find Lingma PID")
        proc.kill()
        return

    # Open process for memory reading
    hproc = find_process(pid)
    if not hproc:
        print(f"Failed to open process (error {ctypes.get_last_error()})")
        proc.kill()
        return

    print(f"Process handle: {hproc}")

    # Read initial values
    base = None
    # Get module base
    h_snapshot = kernel32.CreateToolhelp32Snapshot(0x00000008, pid)  # TH32CS_SNAPMODULE
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
                if me.szExePath.decode('utf-8', errors='replace').lower().endswith('lingma.exe'):
                    base = me.modBaseAddr
                    print(f"Module base: 0x{base:x}")
                    break
                if not kernel32.Module32Next(h_snapshot, ctypes.byref(me)):
                    break
        kernel32.CloseHandle(h_snapshot)

    if not base:
        # Default base from ASLR
        base = 0x7ff600000000  # Typical ASLR base
        print(f"Using assumed base: 0x{base:x}")

    # Calculate absolute addresses
    result_addr = base + RESULT_RVA
    print(f"Result storage at: 0x{result_addr:x}")

    # Read the stored values
    rax_bytes = read_process_memory(hproc, result_addr, 8)
    rcx_bytes = read_process_memory(hproc, result_addr + 8, 8)
    rdx_bytes = read_process_memory(hproc, result_addr + 16, 8)

    if rax_bytes:
        rax_val = struct.unpack('<Q', rax_bytes)[0]
        rcx_val = struct.unpack('<Q', rcx_bytes)[0] if rcx_bytes else 0
        rdx_val = struct.unpack('<Q', rdx_bytes)[0] if rdx_bytes else 0
        print(f"\nInitial values:")
        print(f"  RAX (ptr) = 0x{rax_val:x}")
        print(f"  RCX (len) = {rcx_val}")
        print(f"  RDX (cap) = {rdx_val}")
    else:
        print("Could not read initial values")

    # Now try to trigger getAppSalt via pipe
    if pipe_path:
        print(f"\nConnecting to pipe: {pipe_path}")
        try:
            handle = win32file.CreateFile(
                pipe_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_OVERLAPPED, None
            )
            print("Connected!")

            # Initialize
            print("\nSending initialize...")
            send_rpc(handle, "initialize", {
                "processId": 12345,
                "clientInfo": {"name": "vscode", "version": "1.95.0"},
                "locale": "en-US", "rootPath": "C:/test"
            }, 1)
            time.sleep(2)
            resp = read_resp(handle)
            if resp:
                print(f"  Response: {resp[:200]}")

            # Completion
            print("\nSending textDocument/completion...")
            send_rpc(handle, "textDocument/completion", {
                "textDocument": {"uri": "file:///C:/test/hello.py"},
                "position": {"line": 0, "character": 0}
            }, 2)
            time.sleep(5)
            resp = read_resp(handle, 5000)
            if resp:
                print(f"  Response: {resp[:200]}")

            # Chat
            print("\nSending chat/ask...")
            send_rpc(handle, "chat/ask", {
                "sessionId": "t1", "chatId": "c1",
                "message": "hello", "stream": False
            }, 3)
            time.sleep(10)
            resp = read_resp(handle, 10000)
            if resp:
                print(f"  Response: {resp[:200]}")

            win32file.CloseHandle(handle)
        except Exception as e:
            print(f"Pipe error: {e}")

    # Wait and check for getAppSalt calls
    print("\nChecking for getAppSalt results over 30 seconds...")
    for i in range(6):
        time.sleep(5)
        rax_bytes = read_process_memory(hproc, result_addr, 8)
        if rax_bytes:
            rax_val = struct.unpack('<Q', rax_bytes)[0]
            rcx_val = struct.unpack('<Q', read_process_memory(hproc, result_addr + 8, 8))[0]
            print(f"  [{i*5}s] RAX=0x{rax_val:x} RCX={rcx_val}")

            # Try to read the content
            if rax_val > 0x10000 and rax_val < 0x7FFFFFFFFFFF:
                try:
                    if rcx_val > 0 and rcx_val < 10000:
                        content = read_process_memory(hproc, rax_val, min(rcx_val, 200))
                        if content:
                            print(f"    Content: {content[:100]}")
                except:
                    pass
        else:
            print(f"  [{i*5}s] Could not read")

    kernel32.CloseHandle(hproc)
    proc.kill()
    print("\nDone!")

if __name__ == '__main__':
    main()
