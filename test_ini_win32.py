"""Emitted INI bootstrap using real Windows file/INI APIs in temporary folders.

Game and status APIs stay stubbed. No installed INI, profile or game is opened.
"""
import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import tempfile
import unittest

from test_mod import Machine


class WindowsIniMachine(Machine):
    def __init__(self,path):
        super().__init__()
        self.ini_path=path;self.handles={};self.native_error=0
        self.k=c.WinDLL('kernel32',use_last_error=True)
        self.k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE]
        self.k.CreateFileW.restype=w.HANDLE
        self.k.ReadFile.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p]
        self.k.WriteFile.argtypes=self.k.ReadFile.argtypes
        self.k.CloseHandle.argtypes=[w.HANDLE]
        self.k.GetPrivateProfileStringW.argtypes=[w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.LPWSTR,w.DWORD,w.LPCWSTR]

    def os(self,name):
        a=self.args(7)
        if name=='CreateFileA':
            assert self.string(a[0]).endswith('HT2_AutoSave.ini')
            handle=self.k.CreateFileW(str(self.ini_path),a[1],a[2],None,a[4],a[5],None)
            self.native_error=c.get_last_error()
            if handle==c.c_void_p(-1).value:self.ret(-1,28)
            else:
                fake=700+len(self.handles);self.handles[fake]=handle;self.ret(fake,28)
        elif name in ('ReadFile','WriteFile'):
            buffer=c.create_string_buffer(a[2]);count=w.DWORD()
            if name=='WriteFile':buffer.raw=bytes(self.u.mem_read(a[1],a[2]))
            success=getattr(self.k,name)(self.handles[a[0]],buffer,a[2],c.byref(count),None)
            self.native_error=c.get_last_error()
            if name=='ReadFile' and success and count.value:self.u.mem_write(a[1],buffer.raw[:count.value])
            self.w(a[3],count.value);self.ret(success,20)
        elif name=='CloseHandle':
            success=self.k.CloseHandle(self.handles.pop(a[0]));self.native_error=c.get_last_error()
            self.ret(success,4)
        elif name=='GetLastError':self.ret(self.native_error)
        elif name=='GetPrivateProfileStringA' and self.string(a[5]).endswith('HT2_AutoSave.ini'):
            buffer=c.create_unicode_buffer(a[4])
            n=self.k.GetPrivateProfileStringW(self.string(a[0]),self.string(a[1]),self.string(a[2]),buffer,a[4],str(self.ini_path))
            self.u.mem_write(a[3],buffer.value.encode('cp1251')+b'\0');self.ret(n,24)
        else:super().os(name)


class WindowsIniTests(unittest.TestCase):
    def test_native_file_create_restart_and_custom_settings(self):
        with tempfile.TemporaryDirectory(prefix='HT2_AutoSave_INI_') as directory:
            path=Path(directory)/'HT2_AutoSave.ini'
            first=WindowsIniMachine(path);first.install()
            self.assertEqual(first.status['IniStatus'],'Created');self.assertFalse(first.handles)
            self.assertIn(b'IntervalMinutes = 10',path.read_bytes())
            custom=b'; preserve all bytes\r\n[AutoSave]\r\nOnDriverHire=false\r\nIntervalMinutes=23\r\nUnused=leave me\r\n'
            path.write_bytes(custom)
            again=WindowsIniMachine(path);again.install()
            self.assertEqual(again.status['IniStatus'],'Existing')
            self.assertEqual(again.get('IntervalMinutes'),1380000)
            self.assertEqual(again.get('OnDriverHire'),0)
            self.assertEqual(again.get('OnCargoPickup'),1)
            self.assertEqual(path.read_bytes(),custom);self.assertFalse(again.handles)

    def test_read_only_ini_is_read_without_rewrite(self):
        with tempfile.TemporaryDirectory(prefix='HT2_AutoSave_INI_') as directory:
            path=Path(directory)/'HT2_AutoSave.ini';raw=b'[AutoSave]\r\nMaxAutoSaves=8\r\n'
            path.write_bytes(raw)
            k=c.WinDLL('kernel32',use_last_error=True)
            k.SetFileAttributesW.argtypes=[w.LPCWSTR,w.DWORD]
            self.assertTrue(k.SetFileAttributesW(str(path),1))
            try:
                m=WindowsIniMachine(path);m.install()
                self.assertEqual(m.get('MaxAutoSaves'),8)
                self.assertEqual(m.status['IniStatus'],'Existing')
                self.assertEqual(path.read_bytes(),raw)
            finally:k.SetFileAttributesW(str(path),0x80)


if __name__=='__main__':unittest.main(verbosity=2)
