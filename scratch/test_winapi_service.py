import ctypes
from ctypes import wintypes

advapi32 = ctypes.windll.advapi32

SC_MANAGER_ALL_ACCESS = 0xF003F
SC_MANAGER_CREATE_SERVICE = 0x0002
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_AUTO_START = 0x00000002
SERVICE_DEMAND_START = 0x00000003
SERVICE_ERROR_NORMAL = 0x00000001
DELETE = 0x00010000

# OpenSCManagerW
advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenSCManagerW.restype = wintypes.HANDLE

# CreateServiceW
advapi32.CreateServiceW.argtypes = [
    wintypes.HANDLE,    # hSCManager
    wintypes.LPCWSTR,   # lpServiceName
    wintypes.LPCWSTR,   # lpDisplayName
    wintypes.DWORD,     # dwDesiredAccess
    wintypes.DWORD,     # dwServiceType
    wintypes.DWORD,     # dwStartType
    wintypes.DWORD,     # dwErrorControl
    wintypes.LPCWSTR,   # lpBinaryPathName
    wintypes.LPCWSTR,   # lpLoadOrderGroup
    ctypes.c_void_p,    # lpdwTagId
    wintypes.LPCWSTR,   # lpDependencies
    wintypes.LPCWSTR,   # lpServiceStartName
    wintypes.LPCWSTR    # lpPassword
]
advapi32.CreateServiceW.restype = wintypes.HANDLE

# OpenServiceW
advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
advapi32.OpenServiceW.restype = wintypes.HANDLE

# DeleteService
advapi32.DeleteService.argtypes = [wintypes.HANDLE]
advapi32.DeleteService.restype = wintypes.BOOL

# CloseServiceHandle
advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
advapi32.CloseServiceHandle.restype = wintypes.BOOL

# StartServiceW
advapi32.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
advapi32.StartServiceW.restype = wintypes.BOOL

print("All WinAPI service functions defined successfully!")
