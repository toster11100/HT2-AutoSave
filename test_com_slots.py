"""Real Windows compound storage tests; generated temporary fixtures only.

No game process, native serializers, .pl1 files, copying or fault injection.
Matches the game's root/container/slot modes to check normal slot isolation.
"""
import ctypes as C
from pathlib import Path
import sys
import tempfile
import unittest

if sys.platform != 'win32':
    raise unittest.SkipTest('Windows COM required')

HRESULT = C.c_int32
DWORD = C.c_uint32
PVOID = C.c_void_p
ole = C.OleDLL('ole32')
ole.CoInitializeEx.argtypes = [PVOID, DWORD]
ole.CoInitializeEx.restype = HRESULT
ole.CoUninitialize.argtypes = []
ole.StgCreateDocfile.argtypes = [C.c_wchar_p, DWORD, DWORD, C.POINTER(PVOID)]
ole.StgCreateDocfile.restype = HRESULT
ole.StgOpenStorage.argtypes = [C.c_wchar_p, PVOID, DWORD, PVOID, DWORD, C.POINTER(PVOID)]
ole.StgOpenStorage.restype = HRESULT


def check(hr):
    if hr < 0:
        raise OSError(f'HRESULT 0x{hr & 0xffffffff:08X}')


class Com:
    def __init__(self, pointer):
        self.pointer = pointer

    def invoke(self, index, result, types, *args):
        table = C.cast(self.pointer, C.POINTER(C.POINTER(PVOID))).contents
        call = C.WINFUNCTYPE(result, PVOID, *types)(table[index])
        return call(self.pointer, *args)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.invoke(2, DWORD, [])

    def storage(self, name, create=False, mode=0x10):
        out = PVOID()
        if create:
            hr = self.invoke(5, HRESULT, [C.c_wchar_p, DWORD, DWORD, DWORD, C.POINTER(PVOID)],
                             name, mode, 0, 0, C.byref(out))
        else:
            hr = self.invoke(6, HRESULT,
                             [C.c_wchar_p, PVOID, DWORD, PVOID, DWORD, C.POINTER(PVOID)],
                             name, None, mode, None, 0, C.byref(out))
        check(hr)
        return Com(out)

    def stream(self, name, create=False):
        out = PVOID()
        if create:
            hr = self.invoke(3, HRESULT, [C.c_wchar_p, DWORD, DWORD, DWORD, C.POINTER(PVOID)],
                             name, 0x1011, 0, 0, C.byref(out))
        else:
            hr = self.invoke(4, HRESULT, [C.c_wchar_p, PVOID, DWORD, DWORD, C.POINTER(PVOID)],
                             name, None, 0x10, 0, C.byref(out))
        check(hr)
        return Com(out)

    def write(self, payload):
        count = DWORD()
        buffer = C.create_string_buffer(payload)
        check(self.invoke(4, HRESULT, [PVOID, DWORD, C.POINTER(DWORD)],
                          buffer, len(payload), C.byref(count)))
        if count.value != len(payload):
            raise OSError('Short COM write')

    def read(self, length):
        count = DWORD()
        buffer = C.create_string_buffer(length)
        check(self.invoke(3, HRESULT, [PVOID, DWORD, C.POINTER(DWORD)],
                          buffer, length, C.byref(count)))
        return buffer.raw[:count.value]

    def destroy(self,name):
        return self.invoke(12,HRESULT,[C.c_wchar_p],name)

    def rename(self,old,new):
        return self.invoke(13,HRESULT,[C.c_wchar_p,C.c_wchar_p],old,new)


def root(path, create=False, mode=0x10):
    out = PVOID()
    if create:
        check(ole.StgCreateDocfile(str(path), 0x1012, 0, C.byref(out)))
    else:
        check(ole.StgOpenStorage(str(path), None, mode, None, 0, C.byref(out)))
    return Com(out)


def put(parent, name, value):
    with parent.stream(name, create=True) as stream:
        stream.write(value)


class ComSlotTests(unittest.TestCase):
    def setUp(self):
        check(ole.CoInitializeEx(None, 2))
        self.temp = tempfile.TemporaryDirectory(prefix='HT2_AutoSave_COM_')
        self.path = Path(self.temp.name) / 'synthetic.cfb'
        self.manual = {'manual_1': b'manual-one' * 700, 'manual_2': b'manual-two' * 3}
        self.profile = b'profile sentinel'
        with root(self.path, create=True) as file:
            put(file, 'PROFILE_SENTINEL', self.profile)
            with file.storage('SAVES', create=True, mode=0x1012) as saves:
                for name, payload in self.manual.items():
                    with saves.storage(name, create=True, mode=0x1011) as slot:
                        put(slot, 'PAYLOAD', payload)

    def tearDown(self):
        self.temp.cleanup()
        ole.CoUninitialize()

    def verify(self, autos):
        # Reopen after every release: actual Windows flush/reopen, no mock COM.
        with root(self.path) as file:
            with file.stream('PROFILE_SENTINEL') as stream:
                self.assertEqual(stream.read(9999), self.profile)
            with file.storage('SAVES') as saves:
                for name, payload in dict(self.manual, **autos).items():
                    with saves.storage(name) as slot:
                        with slot.stream('PAYLOAD') as stream:
                            self.assertEqual(stream.read(len(payload) + 1), payload)

    def test_three_slot_rotation_preserves_manual_and_profile_streams(self):
        expected = {}
        for generation in range(1, 10):
            name = f'autosave_{(generation - 1) % 3 + 1}'
            payload = bytes([generation]) * (6000 if generation % 2 else 123)
            with root(self.path, mode=0x12) as file:
                with file.storage('SAVES', mode=0x11) as saves:
                    with saves.storage(name, create=True, mode=0x1011) as slot:
                        put(slot, 'PAYLOAD', payload)
            expected[name] = payload
            self.verify(expected)

    def test_create_overwrite_removes_old_slot_contents_before_new_write(self):
        for write in [True, False]:
            with root(self.path, mode=0x12) as file:
                with file.storage('SAVES', mode=0x11) as saves:
                    with saves.storage('autosave_1', create=True, mode=0x1011) as slot:
                        if write:
                            put(slot, 'PAYLOAD', b'old working save placeholder')
        with root(self.path) as file:
            with file.storage('SAVES') as saves:
                with saves.storage('autosave_1') as slot:
                    with self.assertRaises(OSError) as error:
                        slot.stream('PAYLOAD')
                    self.assertIn('80030002', str(error.exception))  # STG_E_FILENOTFOUND
        self.verify({})

    def test_age_order_renames_closed_slots_without_touching_payload_or_manual(self):
        expected={}
        for generation in range(1,10):
            # Each operation uses the same root/container modes as the ASI.
            with root(self.path,mode=0x12) as file:
                with file.storage('SAVES',mode=0x11) as saves:
                    hr=saves.destroy('autosave_3')
                    self.assertIn(hr&0xffffffff,[0,0x80030002])
                    for old,new in [('autosave_2','autosave_3'),('autosave_1','autosave_2')]:
                        hr=saves.rename(old,new)
                        self.assertIn(hr&0xffffffff,[0,0x80030002])
            # Close/reopen before writing, just like the separate native save.
            with root(self.path,mode=0x12) as file:
                with file.storage('SAVES',mode=0x11) as saves:
                    with saves.storage('autosave_1',create=True,mode=0x1011) as slot:
                        put(slot,'PAYLOAD',bytes([generation])*7000)
            expected={f'autosave_{i}':bytes([generation-i+1])*7000
                      for i in range(1,min(generation,3)+1)}
            self.verify(expected)

    def test_rename_collision_does_not_overwrite_destination(self):
        with root(self.path,mode=0x12) as file:
            with file.storage('SAVES',mode=0x11) as saves:
                self.assertLess(saves.rename('manual_1','manual_2'),0)
        self.verify({})

    def test_exclusive_root_rejects_second_open(self):
        with root(self.path, mode=0x12):
            with self.assertRaises(OSError) as error:
                root(self.path, mode=0x12)
            self.assertEqual(error.exception.winerror & 0xffffffff, 0x80030020)


if __name__ == '__main__':
    unittest.main(verbosity=2)
