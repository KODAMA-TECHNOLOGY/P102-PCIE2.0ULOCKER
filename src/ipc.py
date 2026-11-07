"""Small Windows memory-only status channel; no files or persistent history."""
import ctypes as C
from ctypes import wintypes as W
import json
import struct

SIZE=8192
STATUS=r'Global\P102Gen2StatusV1'
ACTION=r'Local\P102Gen2ActionV1'


class Security(C.Structure):
    _fields_=[('length',W.DWORD),('descriptor',C.c_void_p),('inherit',W.BOOL)]


def dll():
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateFileMappingW.argtypes=[C.c_void_p,C.POINTER(Security),W.DWORD,W.DWORD,W.DWORD,W.LPCWSTR]
    k.CreateFileMappingW.restype=C.c_void_p
    k.OpenFileMappingW.argtypes=[W.DWORD,W.BOOL,W.LPCWSTR]; k.OpenFileMappingW.restype=C.c_void_p
    k.MapViewOfFile.argtypes=[C.c_void_p,W.DWORD,W.DWORD,W.DWORD,C.c_size_t]; k.MapViewOfFile.restype=C.c_void_p
    k.UnmapViewOfFile.argtypes=[C.c_void_p]; k.CloseHandle.argtypes=[C.c_void_p]
    k.LocalFree.argtypes=[C.c_void_p]
    k.CreateEventW.argtypes=[C.POINTER(Security),W.BOOL,W.BOOL,W.LPCWSTR]; k.CreateEventW.restype=C.c_void_p
    k.OpenEventW.argtypes=[W.DWORD,W.BOOL,W.LPCWSTR]; k.OpenEventW.restype=C.c_void_p
    k.SetEvent.argtypes=[C.c_void_p]; k.ResetEvent.argtypes=[C.c_void_p]
    k.WaitForSingleObject.argtypes=[C.c_void_p,W.DWORD]
    k.CreateMutexW.argtypes=[C.c_void_p,W.BOOL,W.LPCWSTR]; k.CreateMutexW.restype=C.c_void_p
    k.ReleaseMutex.argtypes=[C.c_void_p]
    return k


class Channel:
    def __init__(self,name,create=False,public_write=False):
        self.k=dll(); self.handle=None; self.address=None; self.writable=create
        if create:
            adv=C.WinDLL('advapi32',use_last_error=True)
            adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.c_void_p]
            sd=C.c_void_p()
            access='GA' if public_write else 'GR'
            sddl='D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;'+access+';;;BU)'
            if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,C.byref(sd),None): raise C.WinError(C.get_last_error())
            try:
                sa=Security(C.sizeof(Security),sd,False)
                self.handle=self.k.CreateFileMappingW(C.c_void_p(-1),C.byref(sa),4,0,SIZE,name)
            finally: self.k.LocalFree(sd)
        else:
            self.handle=self.k.OpenFileMappingW(4,False,name)
        if not self.handle: raise C.WinError(C.get_last_error())
        self.address=self.k.MapViewOfFile(self.handle,6 if create else 4,0,0,SIZE)
        if not self.address:
            self.k.CloseHandle(self.handle); self.handle=None
            raise C.WinError(C.get_last_error())

    def write(self,value):
        if not self.writable: raise RuntimeError('Read-only channel')
        data=json.dumps(value,ensure_ascii=False).encode('utf8')
        if len(data)>SIZE-12: raise ValueError('Status too large')
        sequence=struct.unpack('<I',C.string_at(self.address+8,4))[0]
        sequence=((sequence+2)&0xFFFFFFFE) or 2
        C.memmove(self.address+8,struct.pack('<I',sequence-1),4)
        C.memmove(self.address+12,data,len(data))
        C.memmove(self.address,b'P102'+struct.pack('<I',len(data)),8)
        C.memmove(self.address+8,struct.pack('<I',sequence),4)

    def read(self):
        for _ in range(3):
            magic,length,sequence=struct.unpack('<4sII',C.string_at(self.address,12))
            if magic!=b'P102' or sequence%2 or not 0<length<=SIZE-12: continue
            data=C.string_at(self.address+12,length)
            if sequence!=struct.unpack('<I',C.string_at(self.address+8,4))[0]: continue
            try: return json.loads(data)
            except (ValueError,UnicodeError): pass
        return {}

    def close(self):
        if self.address: self.k.UnmapViewOfFile(self.address); self.address=None
        if self.handle: self.k.CloseHandle(self.handle); self.handle=None


class StopEvent:
    NAME=r'Global\P102Gen2StopV1'
    def __init__(self,create=False):
        self.k=dll()
        self.handle=self.k.CreateEventW(None,True,False,self.NAME) if create else self.k.OpenEventW(2,False,self.NAME)
        if not self.handle: raise C.WinError(C.get_last_error())
        if create: self.k.ResetEvent(self.handle)
    def is_set(self): return self.k.WaitForSingleObject(self.handle,0)==0
    def set(self):
        if not self.k.SetEvent(self.handle): raise C.WinError(C.get_last_error())
    def close(self):
        if self.handle: self.k.CloseHandle(self.handle); self.handle=None


class WorkerLock:
    def __init__(self):
        self.k=dll(); self.handle=self.k.CreateMutexW(None,False,r'Global\P102Gen2WorkerV1')
        if not self.handle: raise C.WinError(C.get_last_error())
        self.acquired=self.k.WaitForSingleObject(self.handle,0) in (0,0x80)
    def close(self):
        if self.handle:
            if self.acquired: self.k.ReleaseMutex(self.handle)
            self.k.CloseHandle(self.handle); self.handle=None
