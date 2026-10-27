import ctypes
from ctypes import wintypes
import time

advapi32 = ctypes.windll.advapi32

SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_AUTO_START = 0x00000002
SERVICE_ERROR_NORMAL = 0x00000001

advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenSCManagerW.restype = wintypes.HANDLE

advapi32.CreateServiceW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
    wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.LPCWSTR
]
advapi32.CreateServiceW.restype = wintypes.HANDLE

advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenServiceW.restype = wintypes.HANDLE

advapi32.DeleteService.argtypes = [wintypes.HANDLE]
advapi32.DeleteService.restype = wintypes.BOOL

advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
advapi32.CloseServiceHandle.restype = wintypes.BOOL

def try_winapi_create():
    h_scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not h_scm:
        err = ctypes.GetLastError()
        print("OpenSCManagerW failed (expected 5 without elevation):", err)
        return
    print("OpenSCManagerW opened handle:", h_scm)
    advapi32.CloseServiceHandle(h_scm)

try_winapi_create()
