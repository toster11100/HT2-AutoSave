"""Execute original SteamOriginal save code with fake COM objects, never real saves.

Run with the repository's Python/Unicorn toolchain. Native functions under test
are not rewritten. OS, COM and unrelated engine functions are stubbed explicitly.
"""
from pathlib import Path
import hashlib
import struct
import sys
import unittest
import profiles

ROOT = Path(__file__).resolve().parents[1]
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_ERR_READ_UNMAPPED
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_ESP

EXE = profiles.reference('SO')
SHA = '31fbd1dbbe7706183f09a3688482791255db2bfb557c02675374b96796ce2ebd'
STOP, SP, HEAP, API = 0x1000800, 0x20ff000, 0x2010000, 0x1000000
STG_E_WRITEFAULT = 0x8003001d


class ProcessExit(Exception):
    """Stop emulation at the imported ExitProcess, never terminate the test host."""


class Machine:
    def __init__(self):
        raw = EXE.read_bytes()
        if hashlib.sha256(raw).hexdigest() != SHA:
            raise ValueError('Unsupported reference EXE')
        self.u = Uc(UC_ARCH_X86, UC_MODE_32)
        for address, size in [(0x400000, 0x400000),
                              (API, 0x1000), (0x2000000, 0x100000)]:
            self.u.mem_map(address, size)
        self.u.mem_write(0x400000, pefile.PE(data=raw).get_memory_mapped_image())
        self.calls = []
        self.callbacks = {}
        self.next_api = API
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def r(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def w(self, address, value):
        self.u.mem_write(address, struct.pack('<I', value & 0xffffffff))

    def args(self, count):
        sp = self.u.reg_read(UC_X86_REG_ESP)
        return [self.r(sp + 4 + i * 4) for i in range(count)]

    def ret(self, value=0, pop=0):
        sp = self.u.reg_read(UC_X86_REG_ESP)
        self.u.reg_write(UC_X86_REG_EAX, value & 0xffffffff)
        self.u.reg_write(UC_X86_REG_ESP, sp + 4 + pop)
        self.u.reg_write(UC_X86_REG_EIP, self.r(sp))

    def hook(self, u, address, size, data):
        if address in self.callbacks:
            self.callbacks[address]()

    def at(self, address, callback):
        self.callbacks[address] = callback

    def com(self, obj, methods):
        table = obj + 0x100
        self.w(obj, table)
        for offset, callback in methods.items():
            self.w(table + offset, self.next_api)
            self.at(self.next_api, callback)
            self.next_api += 0x10

    def run(self, entry, args):
        self.w(SP, STOP)
        for i, value in enumerate(args):
            self.w(SP + 4 + i * 4, value)
        self.u.reg_write(UC_X86_REG_ESP, SP)
        self.u.emu_start(entry, STOP, count=20000)
        if self.u.reg_read(UC_X86_REG_EIP) != STOP:
            raise AssertionError('Instruction limit reached')
        if self.u.reg_read(UC_X86_REG_ESP) != SP + 4:
            raise AssertionError('Wrong cdecl stack balance')
        return self.u.reg_read(UC_X86_REG_EAX)


def wrapper(fail=None):
    """Real 51D8F0, stub serializers; inspect storage arguments and null failures."""
    m = Machine()
    root, saves, slot, profile, name = [HEAP + n * 0x1000 for n in range(5)]
    m.w(0x6cecd8, profile)
    m.u.mem_write(name, b'autosave_1\0')
    m.at(0x4d90c0, lambda: (m.calls.append(('prepare',)), m.ret()))

    def open_profile():
        args = m.args(2)
        m.calls.append(('profile', args[1]))
        assert args == [profile + 0x278, 2]
        m.ret(0 if fail == 'profile' else root, 8)

    def convert():
        m.ret(m.args(1)[0])  # identity only in the fake COM environment

    def open_saves():
        args = m.args(7)
        m.calls.append(('open_saves', args[2]))
        assert args[0] == root and args[2:6] == [0, 0x11, 0, 0]
        m.w(args[6], 0 if fail == 'open' else saves)
        m.ret(STG_E_WRITEFAULT if fail == 'open' else 0, 28)

    def create_slot():
        args = m.args(6)
        m.calls.append(('create_slot', args[2]))
        assert args[:5] == [saves, name, 0x1011, 0, 0]
        m.w(args[5], 0 if fail == 'create' else slot)
        m.ret(STG_E_WRITEFAULT if fail == 'create' else 0, 24)

    def release():
        m.calls.append(('release', m.args(1)[0]))
        m.ret(0, 4)  # COM refcount, not a save-success result

    def serializer(label):
        def invoke():
            m.calls.append((label, *m.args(2 if label == 'metadata' else 1)))
            m.ret(STG_E_WRITEFAULT if fail == 'serialize' else 0)
        return invoke

    m.at(0x51bfa0, open_profile)
    m.at(0x50bc90, convert)
    m.at(0x5d2e70, lambda: (m.calls.append(('error',)), m.ret()))
    m.at(0x4833a0, serializer('world'))
    m.at(0x51d6d0, serializer('metadata'))
    m.com(root, {0x18: open_saves, 8: release})
    m.com(saves, {0x14: create_slot, 8: release})
    m.com(slot, {8: release})
    return m, lambda: m.run(0x51d8f0, [name, 1])


def metadata(write_error=False, short_write=False):
    """Real 51D6D0, fake IStorage/IStream; all three native Write calls run."""
    m = Machine()
    storage, stream, player, engine, vehicle, settings, app = [HEAP + i * 0x2000 for i in range(7)]
    m.w(0x6f33ac, player)
    m.w(0x6d2078, engine)
    m.w(engine + 0x268, vehicle)
    m.w(0x6cec6c, settings)
    m.w(0x696ca0, app)

    def create():
        args = m.args(6)
        assert args[0] == storage and args[2:5] == [0x1011, 0, 0]
        m.w(args[5], stream)
        m.calls.append(('create_stream',))
        m.ret(0, 24)

    def write():
        args = m.args(4)
        assert args[0] == stream
        m.calls.append(('write', args[2]))
        m.w(args[3], 0 if write_error else args[2] - 1 if short_write else args[2])
        m.ret(STG_E_WRITEFAULT if write_error else 0, 16)

    m.com(storage, {0xc: create})
    m.com(stream, {0x10: write, 8: lambda: m.ret(0, 4)})
    m.at(0x50bc90, lambda: m.ret(m.args(1)[0]))
    m.at(0x56d6c0, lambda: m.ret(0))
    m.at(0x5e4c00, lambda: (m.calls.append(('scene',)), m.ret(0, 4)))
    m.at(0x50c3a0, lambda: m.ret())  # screenshot code, unrelated to this test
    m.at(0x5d2e70, lambda: (m.calls.append(('error',)), m.ret()))
    return m, lambda: m.run(0x51d6d0, [storage, 1])


def use_native_fatal_error(m):
    """Execute real 5D2E70 -> 5D2EF0 -> CRT -> imported ExitProcess.

    Stub only formatting, file logging, clock, callback and CRT locking/table
    walkers. In particular do not replace the fatal dispatcher or CRT exit.
    """
    del m.callbacks[0x5d2e70]
    text = HEAP + 0x8000
    m.u.mem_write(text, b'synthetic error\0')
    m.at(0x5d2e50, lambda: m.ret(text))
    m.at(0x61cca9, lambda: m.ret(0))
    m.at(0x5d2ba0, lambda: (m.calls.append(('log',)), m.ret()))
    m.at(0x61e98a, lambda: m.ret())  # CRT lock
    m.at(0x61e99c, lambda: m.ret())  # CRT function-pointer table walker
    m.at(0x61e993, lambda: m.ret())  # CRT unlock, normally not reached
    m.w(0x72e164, 0)
    m.w(0x77eaf8, 0)

    def local_time():
        m.u.mem_write(m.args(1)[0], bytes(16))
        m.ret(0, 4)

    def exit_process():
        m.calls.append(('ExitProcess', m.args(1)[0]))
        raise ProcessExit()

    clock, cleanup, exit_api = API + 0x500, API + 0x510, API + 0x520
    m.w(0x64b2ac, clock)
    m.w(0x67fb7c, cleanup)
    m.w(0x64b2b8, exit_api)
    m.at(clock, local_time)
    m.at(cleanup, lambda: (m.calls.append(('cleanup',)), m.ret()))
    m.at(exit_api, exit_process)


class NativeSaveTests(unittest.TestCase):
    def test_real_fatal_handler_exits_before_null_use_or_serialization(self):
        for failure in ['profile', 'open', 'create']:
            with self.subTest(failure=failure):
                m, run = wrapper(failure)
                use_native_fatal_error(m)
                with self.assertRaises(ProcessExit):
                    run()
                self.assertEqual(m.calls[-3:], [('log',), ('cleanup',), ('ExitProcess', 0)])
                self.assertFalse(any(c[0] in ('world', 'metadata', 'release') for c in m.calls))

    def test_wrapper_uses_overwrite_slot_and_has_no_success_result(self):
        good, run_good = wrapper()
        failed, run_failed = wrapper('serialize')
        self.assertEqual(run_good(), 0)
        self.assertEqual(run_failed(), 0)
        self.assertEqual(good.calls, failed.calls)
        self.assertIn(('create_slot', 0x1011), good.calls)
        self.assertEqual(sum(c[0] == 'release' for c in good.calls), 3)

    def test_returning_error_stub_profile_failure_reaches_null(self):
        m, run = wrapper('profile')
        with self.assertRaises(UcError) as error:
            run()
        self.assertEqual(error.exception.errno, UC_ERR_READ_UNMAPPED)
        self.assertEqual(m.u.reg_read(UC_X86_REG_EIP), 0x51d926)
        self.assertIn(('error',), m.calls)
        self.assertFalse(any(c[0] == 'world' for c in m.calls))

    def test_returning_error_stub_container_failure_reaches_null(self):
        m, run = wrapper('open')
        with self.assertRaises(UcError) as error:
            run()
        self.assertEqual(error.exception.errno, UC_ERR_READ_UNMAPPED)
        self.assertEqual(m.u.reg_read(UC_X86_REG_EIP), 0x51d966)
        self.assertIn(('error',), m.calls)
        self.assertFalse(any(c[0] == 'world' for c in m.calls))

    def test_returning_error_stub_slot_failure_reaches_serializers_with_null(self):
        m, run = wrapper('create')
        with self.assertRaises(UcError) as error:
            run()
        self.assertEqual(error.exception.errno, UC_ERR_READ_UNMAPPED)
        self.assertEqual(m.u.reg_read(UC_X86_REG_EIP), 0x51d9bc)
        self.assertIn(('error',), m.calls)
        self.assertIn(('world', 0), m.calls)
        self.assertIn(('metadata', 0, 1), m.calls)

    def test_native_metadata_ignores_hresult_and_short_write(self):
        results = []
        for error, short in [(False, False), (True, False), (False, True)]:
            m, run = metadata(error, short)
            results.append((run(), m.calls))
            self.assertEqual([c[1] for c in m.calls if c[0] == 'write'], [24, 4, 24])
            self.assertNotIn(('error',), m.calls)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])


if __name__ == '__main__':
    unittest.main(verbosity=2)
