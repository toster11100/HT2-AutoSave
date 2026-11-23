"""Run the emitted ASI machine code and hook continuations, not a Python model."""
from pathlib import Path
import importlib.util
import os
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import *
spec = importlib.util.spec_from_file_location('autosave_build', ROOT/'build.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
RELEASE = '--release' in sys.argv or os.environ.get('HT2_TEST_RELEASE') == '1'
if '--release' in sys.argv: sys.argv.remove('--release')
COMPAT_RC = os.environ.get('HT2_TEST_COMPAT_RC') == '1' and not RELEASE
IMAGE, MANIFEST = b.build(release=RELEASE, compat_rc=COMPAT_RC)
READY_STATUS, MODULE_NAME = MANIFEST['ready_status'], MANIFEST['module_name']
PROFILE_NAME=MANIFEST['name']
BASE, STOP, SP, HEAP, API = 0x14000000, 0x1000800, 0x20ff000, 0x2010000, 0x1000000
P = lambda value: struct.pack('<I', value & 0xffffffff)


class Machine:
    def __init__(self, config=None, base=BASE):
        self.base = base
        self.u = Uc(UC_ARCH_X86, UC_MODE_32)
        for address,size in [(0x400000,0x400000),(base,0x40000),(API,0x1000),(0x2000000,0x100000)]:
            self.u.mem_map(address,size)
        self.u.mem_write(0x400000,pefile.PE(str(b.EXE)).get_memory_mapped_image())
        self.u.mem_write(base,pefile.PE(data=IMAGE).get_memory_mapped_image())
        self.config = config or {}
        self.ini_content=('[AutoSave]\r\n'+''.join(f'{k}={v}\r\n' for k,v in self.config.items())).encode('ascii')
        self.ini_exists=True;self.ini_failure=None;self.file_error=0
        self.ini_handles=set();self.ini_offset=0;self.ini_writes=0
        self.now, self.foreground, self.save_eax = 100, True, 0
        self.status, self.saves, self.notices, self.protects = {}, [], [], []
        self.fail_protect = 0
        self.native_busy = []
        self.race_calls = 0
        self.storage_slots = {'manual_control':b'manual sentinel'}
        self.rotation_failure = None
        self.rotation_calls = []
        self.open_storage_refs = set()
        self.callbacks = {}
        for i,name in enumerate(b.APIS):
            self.w(base+b.IAT[name],API+i*16)
            self.callbacks[API+i*16] = lambda name=name: self.os(name)
        self.callbacks[0x61cca9] = self.format
        self.callbacks[base+b.R['save_original']] = self.save
        self.callbacks[0x56ae60] = self.notice
        self.callbacks[0x56ce40] = lambda: self.ret(0x789)
        self.callbacks[base+b.R['race_original']] = self.race
        self.u.hook_add(UC_HOOK_CODE,self.hook)
        self.app, self.settings, self.engine, self.vehicle, self.player, self.profile = [HEAP+i*0x8000 for i in range(6)]
        for glob,value in [(0x696ca0,self.app),(0x696848,self.app),(0x6cec6c,self.settings),
                           (0x6d2078,self.engine),(0x6cecd8,self.profile)]: self.w(glob,value)
        self.w(self.app+0x10,3)
        self.w(self.engine+0x268,self.vehicle)
        self.w(self.vehicle+0x509c,self.player)
        self.w(self.player+0x5c,1)
        self.u.mem_write(self.profile+0x278,b'TEST_PROFILE\0')
        root,container=HEAP+0x80000,HEAP+0x81000
        def release():
            obj=self.args(1)[0]
            self.open_storage_refs.remove(obj)
            self.rotation_calls.append(('release',obj))
            self.ret(0,4)
        def profile_open():
            self.assert_args(self.args(2),[self.profile+0x278,2])
            if self.rotation_failure==('profile',):self.ret(0,8);return
            self.open_storage_refs.add(root);self.ret(root,8)
        def container_open():
            a=self.args(7)
            self.assert_args(a[:6],[root,0x67683c,0,0x11,0,0])
            if self.rotation_failure==('open',):self.ret(0x80030005,28);return
            self.open_storage_refs.add(container);self.w(a[6],container);self.ret(0,28)
        def destroy():
            a=self.args(2);name=self.wide_string(a[1])
            assert a[0]==container
            self.rotation_calls.append(('delete',name))
            if self.rotation_failure==('delete',name):self.ret(0x8003001d,8);return
            found=name in self.storage_slots
            self.storage_slots.pop(name,None)
            self.ret(0 if found else 0x80030002,8)
        def rename():
            a=self.args(3);old,new=map(self.wide_string,a[1:])
            assert a[0]==container
            self.rotation_calls.append(('rename',old,new))
            if self.rotation_failure==('rename',old):self.ret(0x8003001d,12);return
            if old not in self.storage_slots:self.ret(0x80030002,12);return
            if new in self.storage_slots:self.ret(0x80030050,12);return
            self.storage_slots[new]=self.storage_slots.pop(old);self.ret(0,12)
        self.callbacks[0x51bfa0]=profile_open
        self.callbacks[0x50bc90]=lambda:self.ret(self.args(1)[0])
        for obj,methods in [(root,{8:release,0x18:container_open}),
                            (container,{8:release,0x30:destroy,0x34:rename})]:
            table=obj+0x100;self.w(obj,table)
            for offset,callback in methods.items():
                api=API+0xc00+len(self.callbacks)*4
                assert api<API+0x1000
                self.w(table+offset,api);self.callbacks[api]=callback

    @staticmethod
    def assert_args(actual,expected):
        assert actual==expected,(actual,expected)

    def wide_string(self,address):
        result=bytearray()
        for offset in range(0,64,2):
            word=bytes(self.u.mem_read(address+offset,2))
            if word==b'\0\0':return result.decode('utf-16le')
            result.extend(word)
        raise AssertionError('Unterminated wide slot name')

    def r(self,address): return struct.unpack('<I',self.u.mem_read(address,4))[0]
    def w(self,address,value): self.u.mem_write(address,P(value))
    def get(self,name): return self.r(self.base+b.F[name])
    def set(self,name,value): self.w(self.base+b.F[name],value)
    def args(self,n):
        sp = self.u.reg_read(UC_X86_REG_ESP)
        return [self.r(sp+4+i*4) for i in range(n)]
    def string(self,address):
        result = bytearray()
        while len(result)<1024:
            value = self.u.mem_read(address,1)
            if value==b'\0': return result.decode('cp1251')
            result += value
            address += 1
        raise AssertionError('Unterminated string')
    def ret(self,value=0,pop=0):
        sp = self.u.reg_read(UC_X86_REG_ESP)
        self.u.reg_write(UC_X86_REG_EIP,self.r(sp))
        self.u.reg_write(UC_X86_REG_ESP,sp+4+pop)
        self.u.reg_write(UC_X86_REG_EAX,value & 0xffffffff)
    def hook(self,u,address,size,data):
        if address in self.callbacks: self.callbacks[address]()
    def os(self,name):
        a = self.args(6)
        if name=='GetModuleHandleA': self.ret(0x400000 if a[0]==0 else 0,4)
        elif name=='GetModuleHandleExA':
            assert a[0]==5 and a[1]==self.base
            self.w(a[2],self.base); self.ret(1,12)
        elif name=='GetModuleFileNameA':
            value = ('C:\\HT2\\plugins\\'+MODULE_NAME if a[0] else 'C:\\HT2\\king.exe').encode()
            self.u.mem_write(a[1],value+b'\0'); self.ret(len(value),12)
        elif name=='VirtualProtect':
            self.protects.append(tuple(a[:3])); self.w(a[3],0x20)
            self.ret(0 if len(self.protects)==self.fail_protect else 1,16)
        elif name=='FlushInstructionCache': self.ret(1,12)
        elif name=='GetPrivateProfileStringA':
            key = self.string(a[1]); path = self.string(a[5])
            assert path in ('C:\\HT2\\plugins\\HT2_AutoSave.ini','C:\\HT2\\TRUCK.INI'), path
            values=self.config if path.endswith('TRUCK.INI') else {}
            if not path.endswith('TRUCK.INI'):
                for line in self.ini_content.decode('cp1251').splitlines():
                    if '=' in line and not line.lstrip().startswith((';','#')):
                        k,v=line.split('=',1);values[k.strip()]=v.strip()
            value = str(values.get(key,self.string(a[2]))).encode('cp1251')[:a[4]-1]
            self.u.mem_write(a[3],value+b'\0'); self.ret(len(value),24)
        elif name=='WritePrivateProfileStringA':
            assert self.string(a[3])=='C:\\HT2\\plugins\\HT2_AutoSave_Status.ini'
            self.status[self.string(a[1])] = self.string(a[2]); self.ret(1,16)
        elif name=='GetTickCount': self.ret(self.now)
        elif name=='GetCurrentProcessId': self.ret(1000)
        elif name=='GetForegroundWindow': self.ret(0x1234 if self.foreground else 0)
        elif name=='GetWindowThreadProcessId': self.w(a[1],1000); self.ret(4321,8)
        elif name=='GetProcAddress': self.ret(0,8)
        elif name=='CreateFileA':
            a=self.args(7)
            assert self.string(a[0])=='C:\\HT2\\plugins\\HT2_AutoSave.ini'
            assert a[2]==3 and a[3]==0 and a[5]==0x80 and a[6]==0
            if self.ini_failure=='open':self.file_error=5;self.ret(-1,28);return
            if a[4]==3:
                assert a[1]==0x80000000
                if not self.ini_exists:self.file_error=2;self.ret(-1,28);return
            else:
                assert a[4]==1 and a[1]==0x40000000
                if self.ini_failure=='create':self.file_error=5;self.ret(-1,28);return
                if self.ini_exists:self.file_error=80;self.ret(-1,28);return
                self.ini_exists=True;self.ini_content=b''
            self.ini_offset=0;self.ini_handles.add(700);self.ret(700,28)
        elif name=='ReadFile':
            assert a[0] in self.ini_handles
            if self.ini_failure=='read':self.file_error=30;self.ret(0,20);return
            value=self.ini_content[self.ini_offset:self.ini_offset+a[2]]
            self.ini_offset+=len(value)
            if value:self.u.mem_write(a[1],value)
            self.w(a[3],len(value));self.ret(1,20)
        elif name=='WriteFile':
            assert a[0] in self.ini_handles
            self.ini_writes+=1
            if self.ini_failure=='write':self.file_error=29;self.ret(0,20);return
            count=a[2]-(1 if self.ini_failure=='short' else 0)
            self.ini_content=bytes(self.u.mem_read(a[1],count));self.w(a[3],count);self.ret(1,20)
        elif name=='CloseHandle':
            self.ini_handles.remove(a[0]);self.ret(1,4)
        elif name=='GetLastError':self.ret(self.file_error)
        else: raise AssertionError(name)
    def format(self):
        target,fmt,number = self.args(3)
        assert self.string(fmt)=='autosave_%u'
        self.u.mem_write(target,f'autosave_{number}'.encode()+b'\0'); self.ret()
    def save(self):
        name,flag = self.args(2)
        assert self.get('busy')==1
        self.native_busy.append(self.get('busy'))
        assert not self.open_storage_refs
        self.saves.append((self.string(name),flag,self.get('last_reason')))
        self.storage_slots[self.string(name)]=len(self.saves)
        self.ret(self.save_eax)
    def notice(self):
        assert self.saves and self.get('busy')==0
        self.notices.append(self.string(self.args(1)[0])); self.ret()
    def race(self):
        self.race_calls += 1
        actor = self.args(1)[0]
        self.w(actor+0x60,self.r(actor+0x60)&~0x4000)
        self.ret(0xface)
    def run(self,address,args=(),end=STOP,regs=None,limit=100000):
        self.w(SP,STOP)
        for i,value in enumerate(args): self.w(SP+4+i*4,value)
        self.u.reg_write(UC_X86_REG_ESP,SP)
        for reg,value in (regs or {}).items(): self.u.reg_write(reg,value)
        self.u.emu_start(address,end,count=limit)
        assert self.u.reg_read(UC_X86_REG_EIP)==end, hex(self.u.reg_read(UC_X86_REG_EIP))
    def install(self):
        self.run(self.base+b.R['entry'],[self.base,1,0])
        assert self.u.reg_read(UC_X86_REG_ESP)==SP+16
        self.pump()
    def pump(self): self.run(self.base+b.R['pump_hook'],end=0x59814c)
    def clock(self,delta=250):
        self.now = (self.now+delta)&0xffffffff
        self.run(self.base+b.R['clock_hook'],end=0x4e108c)
    def event(self,name,valid=True,player=None):
        frame = HEAP+0x70000
        self.w(frame+8,self.player if player is None else player)
        out = frame+0x100
        self.w(frame+0x18,out); self.w(frame+0x10,out)
        self.w(out,0 if valid else -1)
        self.u.mem_write(SP+0x13,bytes([int(valid)]))
        target = dict(pickup_hook=0x444d7e,delivery_hook=0x444576,present_hook=0x44376f)[name]
        self.run(self.base+b.R[name],end=target,regs={UC_X86_REG_EBP:frame})
    def mature(self):
        for _ in range(5): self.clock()
        self.pump()


class AutoSaveTests(unittest.TestCase):
    def test_pe_imports_are_disjoint_and_match_runtime_calls(self):
        pe = pefile.PE(data=IMAGE)
        expected = {
            b'KERNEL32.dll': b.APIS[:b.KERNEL_COUNT],
            b'USER32.dll': b.APIS[b.KERNEL_COUNT:],
        }
        if RELEASE or COMPAT_RC:
            expected[b'CRYPT32.dll'] = ['CryptHashCertificate2']
        self.assertEqual(
            {library.dll: [entry.name.decode('ascii') for entry in library.imports]
             for library in pe.DIRECTORY_ENTRY_IMPORT},
            expected,
        )
        addresses = [entry.address for library in pe.DIRECTORY_ENTRY_IMPORT for entry in library.imports]
        self.assertEqual(len(addresses), len(set(addresses)))

    def machine(self,**kwargs):
        m = Machine(**kwargs); m.install()
        self.assertEqual(m.status.get('Result'),READY_STATUS)
        return m

    def test_defaults_actual_config_parser_and_disabled(self):
        m = self.machine()
        expected_version=b.RELEASE_VERSION if RELEASE else (b.COMPAT_VERSION if COMPAT_RC else b.VERSION)
        self.assertEqual(m.status['Version'],expected_version)
        self.assertEqual(MANIFEST['version'],expected_version)
        self.assertEqual(m.status['RotationError'],'00000000')
        self.assertEqual(m.status['Profile'],PROFILE_NAME)
        self.assertEqual([m.get(name) for name,_,_ in b.CONFIG],[1,1,1,1,1,600000,3,1,1,1])
        for key,value,expected in [('Enabled','false',0),('OnCargoPickup',' NO ',0),
                ('OnCargoDelivery','OFF',0),('OnRaceVictory','0',0),('IntervalEnabled',' yes ',1),
                ('IntervalMinutes','0',600000),('IntervalMinutes','-1',600000),
                ('IntervalMinutes','999999999999999999999999',600000),
                ('IntervalMinutes','2',120000),('MaxAutoSaves','0',3),('MaxAutoSaves','99',99),
                ('MaxAutoSaves','100',3),('ShowNotification','nonsense',1),('MaxAutoSaves','1'*80,3)]:
            with self.subTest(key=key,value=value):
                n = Machine(config={key:value}); n.install()
                self.assertEqual(n.get(key),expected)
                if key=='Enabled': self.assertEqual(n.status['Result'],'Disabled')

    def test_first_run_creates_all_defaults_and_restart_preserves_custom_ini(self):
        m=Machine();m.ini_exists=False;m.install()
        self.assertEqual(m.status['IniStatus'],'Created')
        self.assertEqual(m.status['IniError'],'00000000')
        self.assertEqual(m.ini_writes,1);self.assertFalse(m.ini_handles)
        for name,_,_ in b.CONFIG:self.assertIn((name+' = ').encode(),m.ini_content)
        raw=b'; keep my comment\r\n[AutoSave]\r\nIntervalMinutes=7\r\nOnCargoPickup=false\r\nUnknownKey=keep\r\n'
        n=Machine();n.ini_content=raw;n.install()
        self.assertEqual(n.ini_content,raw);self.assertEqual(n.ini_writes,0)
        self.assertEqual(n.status['IniStatus'],'Existing')
        self.assertEqual(n.get('IntervalMinutes'),420000)
        self.assertEqual(n.get('OnCargoPickup'),0)
        self.assertEqual(n.get('OnDriverHire'),1)
        n.ini_content=raw.replace(b'7',b'9');n.pump()
        self.assertEqual(n.get('IntervalMinutes'),420000)
        restart=Machine();restart.ini_content=n.ini_content;restart.install()
        self.assertEqual(restart.get('IntervalMinutes'),540000)
        cache=Machine()
        def cached_module_path():
            args=cache.args(3)
            text=('C:\\Workshop\\'+MODULE_NAME if args[0] else 'C:\\HT2\\king.exe').encode()
            cache.u.mem_write(args[1],text+b'\0');cache.ret(len(text),12)
        cache.callbacks[API+b.APIS.index('GetModuleFileNameA')*16]=cached_module_path
        cache.install()  # File APIs assert the GAME/plugins path, not Workshop.
        self.assertEqual(cache.status['IniStatus'],'Existing')

    def test_ini_failures_use_all_defaults_and_report_error(self):
        for failure,state in [('open','ReadFailed'),('read','ReadFailed'),('create','CreateFailed'),
                              ('write','WriteFailed'),('short','WriteFailed')]:
            with self.subTest(failure=failure):
                m=Machine(config={'IntervalMinutes':'7','OnCargoPickup':'false'})
                before=m.ini_content;m.ini_failure=failure
                if failure in ('create','write','short'):m.ini_exists=False
                m.install()
                self.assertEqual(m.status['IniStatus'],state)
                self.assertNotEqual(m.status['IniError'],'00000000')
                self.assertFalse(m.ini_handles)
                self.assertEqual([m.get(k) for k,_,_ in b.CONFIG],[1,1,1,1,1,600000,3,1,1,1])
                if failure in ('open','read'):self.assertEqual(m.ini_content,before);self.assertEqual(m.ini_writes,0)

    def test_create_new_race_preserves_file_created_by_other_actor(self):
        class Race(Machine):
            def os(self,name):
                if name=='CreateFileA' and self.args(7)[4]==1:
                    self.ini_exists=True;self.ini_content=b'[AutoSave]\r\nIntervalMinutes=17\r\n'
                super().os(name)
        m=Race();m.ini_exists=False;m.install()
        self.assertEqual(m.ini_writes,0);self.assertEqual(m.get('IntervalMinutes'),1020000)
        self.assertEqual(m.status['IniStatus'],'Existing')

    def test_notifications_support_all_five_language_settings(self):
        for prefix,message in [('eng','AUTOSAVE'),('rus','АВТОСОХРАНЕНИЕ'),
                               ('fre','SAUVEGARDE AUTO'),('ger','AUTOMATISCHES SPEICHERN'),
                               ('spa','GUARDADO AUTOMATICO')]:
            with self.subTest(language=prefix):
                m=self.machine(config={'langv':prefix})
                m.event('pickup_hook');m.mature()
                self.assertEqual(m.notices,[message])

    def business_event(self,m,kind,actor=None,correct_owner=True):
        actor=m.player if actor is None else actor
        if kind=='vehicle':
            m.w(SP+0x14,actor)
            m.run(0x56ff86,end=0x56ff90)
        else:
            driver=HEAP+0x60000
            m.w(SP+0x3c,actor);m.w(SP+0x40,driver)
            m.w(driver+0xb0,actor if correct_owner else 0)
            m.run(0x476f0b,end=0x476f11)

    def test_purchase_and_hire_enqueue_once_and_do_not_mutate_business_state(self):
        for kind,reason in [('vehicle',16),('driver',32)]:
            with self.subTest(kind=kind):
                m=self.machine()
                m.u.mem_write(m.player+0x88,struct.pack('<d',12345.0))
                money=bytes(m.u.mem_read(m.player+0x88,8))
                company=bytes(m.u.mem_read(m.player+0x90,0x20))
                owner=m.r(m.vehicle+0x509c)
                self.business_event(m,kind);self.business_event(m,kind)
                self.assertEqual(m.get('pending'),reason)
                self.assertFalse(m.saves)
                self.assertEqual(bytes(m.u.mem_read(m.player+0x88,8)),money)
                self.assertEqual(bytes(m.u.mem_read(m.player+0x90,0x20)),company)
                self.assertEqual(m.r(m.vehicle+0x509c),owner)
                m.mature()
                self.assertEqual(m.saves,[('autosave_1',0,reason)])

    def test_new_event_switches_are_independent_and_require_player_owner(self):
        for kind,key,other,reason in [('vehicle','OnVehiclePurchase','OnDriverHire',16),
                                      ('driver','OnDriverHire','OnVehiclePurchase',32)]:
            with self.subTest(kind=kind):
                m=self.machine(config={key:'false'})
                self.business_event(m,kind);m.mature();self.assertFalse(m.saves)
                n=self.machine(config={other:'OFF',key:' YES '})
                ai=HEAP+0x50000;n.w(ai+0x5c,2)
                self.business_event(n,kind,actor=ai);self.assertEqual(n.get('pending'),0)
                self.business_event(n,kind);n.mature()
                self.assertEqual(n.saves[0][2],reason)
        m=self.machine();self.business_event(m,'driver',correct_owner=False)
        self.assertEqual(m.get('pending'),0)

    def test_all_event_reasons_merge_with_interval(self):
        m=self.machine();m.set('pending',8);m.event('pickup_hook');m.event('delivery_hook')
        m.w(0x68d164,0);m.w(0x68d188,0);m.w(0x68a980,HEAP);m.w(0x68a984,HEAP+4)
        m.w(m.player+0x60,0x4000);m.run(m.base+b.R['race_hook'],[m.player])
        self.business_event(m,'vehicle');self.business_event(m,'driver')
        self.assertEqual(m.get('pending'),63)
        m.mature();self.assertEqual(m.saves,[('autosave_1',0,63)])

    def test_native_hire_rejections_do_not_reach_success_hook(self):
        for case,expected in [('self',-5),('already_hired',-4),('employer_owned',-12)]:
            with self.subTest(case=case):
                m=self.machine();m.u.mem_map(0,0x1000)
                driver=HEAP+0x60000
                m.w(driver+0xb0,m.player if case=='already_hired' else 0)
                m.w(m.player+0xb0,driver if case=='employer_owned' else 0)
                m.run(0x476bc0,[m.player,m.player if case=='self' else driver])
                self.assertEqual(m.u.reg_read(UC_X86_REG_EAX),expected&0xffffffff)
                self.assertEqual(m.get('pending'),0)

    def test_native_insufficient_hire_funds_branch_has_no_event(self):
        from keystone import Ks,KS_ARCH_X86,KS_MODE_32
        m=self.machine();m.u.mem_map(0,0x1000)
        driver=HEAP+0x60000
        m.u.mem_write(m.player+0x88,struct.pack('<d',0.0))
        m.u.mem_write(driver+0x360,struct.pack('<d',100.0))
        m.u.mem_write(API+0x900,bytes(Ks(KS_ARCH_X86,KS_MODE_32).asm('fninit; fld1; ret')[0]))
        m.run(API+0x900)
        m.w(SP+0x3c,m.player);m.w(SP+0x40,driver);m.w(SP+0x38,STOP)
        m.callbacks[0x417660]=lambda:m.ret(1)
        m.callbacks[0x40e270]=lambda:m.ret(HEAP)
        m.callbacks[0x56ae60]=lambda:m.ret()
        m.u.reg_write(UC_X86_REG_ESP,SP);m.u.reg_write(UC_X86_REG_EDX,driver)
        m.u.reg_write(UC_X86_REG_ECX,m.player)
        m.u.emu_start(0x476d36,STOP,count=10000)
        self.assertEqual(m.u.reg_read(UC_X86_REG_EAX),(-6)&0xffffffff)
        self.assertEqual(m.get('pending'),0)
        self.assertEqual(struct.unpack('<d',m.u.mem_read(m.player+0x88,8))[0],0.0)

    def test_native_failed_purchase_branch_skips_purchase_hook(self):
        for failure in [1,(-6)&0xffffffff,(-1)&0xffffffff]:
            m=self.machine();m.w(SP+0x160,STOP)
            m.u.reg_write(UC_X86_REG_ESP,SP-12);m.u.reg_write(UC_X86_REG_EAX,failure)
            m.u.emu_start(0x56feab,STOP,count=10000)
            self.assertEqual(m.u.reg_read(UC_X86_REG_EAX),failure)
            self.assertEqual(m.get('pending'),0)

    def test_native_hire_owner_assignment_precedes_request(self):
        m=self.machine();driver=HEAP+0x60000
        m.w(SP+0x40,driver);m.w(SP+0x1c,m.player)
        m.u.reg_write(UC_X86_REG_ESP,SP)
        m.u.emu_start(0x476e3a,0x476e50,count=1000)
        self.assertEqual(m.r(driver+0xb0),m.player)
        self.assertEqual(m.get('pending'),0)
        self.business_event(m,'driver');self.assertEqual(m.get('pending'),32)

    def test_native_purchase_tail_preserves_steam_achievement_and_sets_new_owner(self):
        for steam in [False,True]:
            with self.subTest(steam=steam):
                m=Machine();trace=[]
                new_vehicle=HEAP+0x50000;old_vehicle=m.vehicle
                new_props=HEAP+0x60000;old_props=HEAP+0x64000
                m.w(new_vehicle+0x5460,new_props);m.w(old_vehicle+0x5460,old_props)
                def select_vehicle():
                    self.assertEqual(m.args(1)[0],new_vehicle)
                    trace.append('native_select');m.w(m.engine+0x268,new_vehicle);m.ret(0,4)
                m.callbacks[0x531cc0]=select_vehicle
                if steam:
                    module=pefile.PE(str(b.exe_profiles.input_file('ht2ach.dll')));base=0x16000000
                    module.relocate_image(base);m.u.mem_map(base,0x40000)
                    m.u.mem_write(base,module.get_memory_mapped_image())
                    m.w(base+0x308b4,0x531cc0)
                    def achievement():
                        trace.append('achievement');self.assertEqual(m.get('pending'),0);m.ret(0,4)
                    m.callbacks[base+0x7730]=achievement
                    call=b'\xe8'+P(base+0x7ac0-(0x56ff07+5));m.u.mem_write(0x56ff07,call)
                else:call=bytes(m.u.mem_read(0x56ff07,5))
                m.install();self.assertEqual(m.status['Result'],READY_STATUS)
                self.assertEqual(bytes(m.u.mem_read(0x56ff07,5)),call)
                m.callbacks[0x597570]=lambda:m.ret()
                def finish_physics():
                    self.assertEqual(m.args(3),[1,1,new_vehicle]);m.ret(0,12)
                m.callbacks[0x4ebaa0]=finish_physics
                m.w(SP+0x14,m.player);m.w(SP-4,new_vehicle);m.w(0x6f2dc0,0)
                m.u.reg_write(UC_X86_REG_ESP,SP-4)
                for reg,value in [(UC_X86_REG_ECX,m.engine),(UC_X86_REG_EBX,new_vehicle),
                                  (UC_X86_REG_EBP,old_vehicle),(UC_X86_REG_EDI,1),(UC_X86_REG_ESI,0)]:
                    m.u.reg_write(reg,value)
                m.u.emu_start(0x56ff07,0x56ff90,count=10000)
                self.assertEqual(m.u.reg_read(UC_X86_REG_EIP),0x56ff90)
                self.assertEqual(trace,['native_select','achievement'] if steam else ['native_select'])
                self.assertEqual(m.r(m.engine+0x268),new_vehicle)
                self.assertEqual(m.r(new_vehicle+0x509c),m.player)
                self.assertEqual(m.r(old_vehicle+0x509c),0)
                self.assertEqual(m.get('pending'),16);self.assertFalse(m.saves)
                m.mature();self.assertEqual(m.saves,[('autosave_1',0,16)])

    def test_hooks_and_other_game_bytes_unchanged(self):
        m = Machine(); before = bytes(m.u.mem_read(0x400000,0x400000)); m.install()
        expected = bytearray(before)
        for name,va,n in b.HOOKS:
            opcode = b'\xe9'
            expected[va-0x400000:va-0x400000+n] = opcode+P(m.base+b.R[name]-(va+5))+b'\x90'*(n-5)
        self.assertEqual(bytes(m.u.mem_read(0x400000,0x400000)),bytes(expected))

    def test_every_hook_conflict_rejects_features(self):
        for name,va,n in b.HOOKS:
            with self.subTest(name=name):
                m = Machine(); m.u.mem_write(va,b'\xe9')
                m.run(m.base+b.R['entry'],[m.base,1,0])
                if name=='pump_hook':
                    self.assertFalse(m.protects)
                else:
                    m.pump(); self.assertEqual(m.status.get('Result'),'SignatureConflict')
                    self.assertEqual(m.status.get('ConflictAddress'),f'{va:08X}')
                    self.assertNotEqual(m.get('ready'),1)

    def test_unsupported_profile_metadata_does_not_patch(self):
        for change in [8,0x50]:
            m = Machine(); pe_header = 0x400000+m.r(0x40003c)
            m.w(pe_header+change,0)
            m.run(m.base+b.R['entry'],[m.base,1,0])
            self.assertFalse(m.protects)
        m=Machine();m.u.mem_unmap(0x400000,0x400000)
        m.callbacks[API+b.APIS.index('GetModuleHandleA')*16]=lambda:m.ret(0x800000,4)
        m.run(m.base+b.R['entry'],[m.base,1,0])
        self.assertFalse(m.protects)

    def test_unknown_profile_metadata_is_rejected(self):
        for offset in [8,0x50]:
            with self.subTest(offset=offset):
                m = Machine()
                header=0x400000+m.r(0x40003c)
                m.w(header+offset,0x1234)
                before=bytes(m.u.mem_read(0x400000,0x400000))
                m.run(m.base+b.R['entry'],[m.base,1,0])
                self.assertFalse(m.protects)
                self.assertEqual(bytes(m.u.mem_read(0x400000,0x400000)),before)

    def test_relocated_asi_and_single_install(self):
        m = self.machine(base=0x17000000)
        count = len(m.protects)
        m.pump(); m.pump()
        self.assertEqual(len(m.protects),count)
        m.event('pickup_hook'); m.mature()
        self.assertEqual(m.saves[0][:2],('autosave_1',0))

    def test_three_events_coalesce_and_rotate(self):
        m = self.machine()
        for i in range(5):
            m.event('pickup_hook'); m.event('pickup_hook'); m.event('delivery_hook')
            m.pump(); self.assertEqual(len(m.saves),i)
            m.mature()
        self.assertEqual([s[0] for s in m.saves],['autosave_1']*5)
        self.assertEqual([m.storage_slots[f'autosave_{i}'] for i in range(1,4)],[5,4,3])
        self.assertTrue(all(s[2]==3 for s in m.saves))
        self.assertEqual(len(m.notices),5)

    def test_ordered_slots_restart_gaps_and_profile_isolation(self):
        m=self.machine()
        m.storage_slots.update(autosave_1='newest',autosave_3='oldest',autosave_7='outside limit')
        m.event('pickup_hook');m.mature()
        self.assertEqual(m.storage_slots,{'manual_control':b'manual sentinel',
            'autosave_1':1,'autosave_2':'newest','autosave_7':'outside limit'})
        # Restart has no next-slot state to persist: move the existing hierarchy.
        n=self.machine();n.storage_slots=dict(m.storage_slots)
        n.event('delivery_hook');n.mature()
        self.assertEqual(n.storage_slots['autosave_3'],'newest')
        self.assertEqual(n.storage_slots['autosave_2'],1)
        # The current profile's native opener is used again on every request.
        n.profile=HEAP+0x76000;n.w(0x6cecd8,n.profile)
        n.u.mem_write(n.profile+0x278,b'SECOND_PROFILE\0')
        n.storage_slots={'manual_control':b'second profile'}
        n.event('pickup_hook');n.mature()
        self.assertEqual(n.storage_slots,{'manual_control':b'second profile','autosave_1':2})

    def test_ordered_slot_limits_and_wide_names(self):
        for count in [1,2,10,99]:
            with self.subTest(count=count):
                m=self.machine(config={'MaxAutoSaves':str(count)})
                m.storage_slots.update({f'autosave_{i}':f'old-{i}' for i in range(1,count+1)})
                m.event('pickup_hook');m.mature()
                self.assertEqual(m.storage_slots['autosave_1'],1)
                for i in range(2,count+1):
                    self.assertEqual(m.storage_slots[f'autosave_{i}'],f'old-{i-1}')
                self.assertEqual(m.storage_slots['manual_control'],b'manual sentinel')
                self.assertFalse(m.open_storage_refs)
                self.assertEqual(bool(m.rotation_calls),count!=1)

    def test_rotation_errors_release_handles_disable_once_and_skip_native_save(self):
        failures=[('profile',),('open',),('delete','autosave_3'),
                  ('rename','autosave_2'),('rename','autosave_1')]
        for failure in failures:
            with self.subTest(failure=failure):
                m=self.machine();m.rotation_failure=failure
                m.storage_slots.update(autosave_1='A',autosave_2='B',autosave_3='C')
                m.event('pickup_hook');m.mature()
                self.assertEqual(m.status['Result'],'RotationFailed')
                self.assertTrue(int(m.status['RotationError'],16)&0x80000000)
                self.assertFalse(m.saves);self.assertFalse(m.notices)
                self.assertFalse(m.open_storage_refs)
                self.assertEqual(m.get('busy'),0);self.assertEqual(m.get('in_tick'),0)
                self.assertEqual(m.storage_slots['manual_control'],b'manual sentinel')
                if failure==('rename','autosave_1'):
                    self.assertEqual(m.storage_slots['autosave_3'],'B')
                    self.assertEqual(m.storage_slots['autosave_1'],'A')
                    self.assertNotIn('autosave_2',m.storage_slots)
                previous=list(m.rotation_calls)
                m.event('delivery_hook');m.mature();m.pump()
                self.assertEqual(m.rotation_calls,previous)

    def test_manual_native_save_never_shifts_autoslots(self):
        m=self.machine()
        before=dict(m.storage_slots,autosave_1='A',autosave_2='B',autosave_3='C')
        m.storage_slots=dict(before)
        name=HEAP+0x74000;m.u.mem_write(name,b'manual_control\0')
        m.run(0x51d8f0,[name,1])
        self.assertFalse(m.rotation_calls)
        for key in ['autosave_1','autosave_2','autosave_3']:
            self.assertEqual(m.storage_slots[key],before[key])

    def test_present_pickup_empty_operations_ai_and_event_toggles(self):
        for event,key in [('pickup_hook','OnCargoPickup'),('present_hook','OnCargoPickup'),('delivery_hook','OnCargoDelivery')]:
            with self.subTest(event=event):
                m = self.machine()
                m.event(event,False); self.assertEqual(m.get('pending'),0)
                ai = HEAP+0x60000; m.w(ai+0x5c,2)
                m.event(event,player=ai); self.assertEqual(m.get('pending'),0)
                m.event(event); self.assertNotEqual(m.get('pending'),0)
                m.mature(); self.assertEqual(len(m.saves),1)
                n = self.machine(config={key:'false'})
                n.event(event); n.mature(); self.assertFalse(n.saves)

    def test_race_win_after_native_reward_loss_and_repeated_finish(self):
        for place,mode,prize,racing,enabled in [(0,0,True,True,True),(1,0,True,True,True),
                (0,1,True,True,True),(0,0,False,True,True),(0,0,True,False,True),
                (0,0,True,True,False)]:
            with self.subTest(place=place,mode=mode,prize=prize,racing=racing,enabled=enabled):
                m = self.machine(config={'OnRaceVictory':str(enabled)})
                m.w(0x68d164,place); m.w(0x68d188,mode)
                m.w(0x68a980,HEAP+0x70000); m.w(0x68a984,HEAP+0x70000+(4 if prize else 0))
                m.w(m.player+0x60,0x4000 if racing else 0)
                m.run(m.base+b.R['race_hook'],[m.player])
                self.assertEqual(m.race_calls,1)
                self.assertEqual(m.get('pending')==4,place==0 and mode==0 and prize and racing and enabled)
                m.mature(); count = len(m.saves)
                m.run(m.base+b.R['race_hook'],[m.player]); m.mature()
                self.assertEqual(len(m.saves),count)

    def test_pause_menu_loading_focus_and_deferred_request(self):
        for location in ['pause','overlay','phone','menu','loading','focus','replay','mode','no_vehicle','no_profile']:
            with self.subTest(location=location):
                m = self.machine(); m.clock(); m.clock()
                m.event('delivery_hook')
                changes = {'pause':(m.settings+0x504,1),'overlay':(m.settings+0x508,1),
                    'phone':(m.settings+0x510,1),'menu':(0x696848,0),'loading':(0x69689c,1),
                    'replay':(m.settings+0x524,1),'mode':(m.settings+0x514,2),
                    'no_vehicle':(m.engine+0x268,0),'no_profile':(0x6cecd8,0)}
                elapsed = m.get('elapsed')
                if location=='focus': m.foreground=False
                else:
                    address,value=changes[location]; old=m.r(address); m.w(address,value)
                for _ in range(5): m.clock(1000); m.pump()
                self.assertEqual(m.get('elapsed'),elapsed); self.assertFalse(m.saves)
                if location=='focus': m.foreground=True
                else: m.w(address,old)
                m.mature(); self.assertEqual(len(m.saves),1)

    def test_active_interval_event_priority_and_clock_wrap(self):
        m = self.machine(config={'IntervalMinutes':'1'})
        m.now=0xfffffff0; m.clock(0)
        for _ in range(60): m.clock(1000)
        self.assertEqual(m.get('pending'),8)
        m.event('pickup_hook'); m.pump(); self.assertFalse(m.saves)
        m.mature(); self.assertEqual(m.saves[0][2],9)
        self.assertEqual(m.get('elapsed'),0)
        m.pump(); self.assertEqual(len(m.saves),1)

    def test_interval_standing_still_variable_frame_rate_uses_wall_clock(self):
        for frame_ms in [16,33,100,1000]:
            with self.subTest(frame_ms=frame_ms):
                m=self.machine(config={'IntervalMinutes':'1'})
                # No movement, input events or vehicle velocity changes.
                m.clock(0)
                started=m.now
                while not m.saves:
                    m.clock(frame_ms);m.pump()
                    self.assertLess(m.now-started,61001)
                self.assertGreaterEqual(m.now-started,60000)
                self.assertLess(m.now-started,60000+frame_ms)
                self.assertEqual(m.saves[0][2],8)

    def test_interval_delay_sources_are_separate_from_counted_active_minute(self):
        # Prove a >2s gap is discarded rather than silently counted.
        m=self.machine(config={'IntervalMinutes':'1'})
        m.clock(0)
        for _ in range(30):m.clock(1000);m.pump()
        m.clock(47000);m.pump()
        self.assertEqual(m.get('elapsed'),30000)
        for _ in range(30):m.clock(1000);m.pump()
        self.assertEqual(len(m.saves),1)
        # A completed active minute can wait for the save pump independently.
        n=self.machine(config={'IntervalMinutes':'1'})
        n.clock(0)
        for _ in range(60):n.clock(1000)
        self.assertEqual(n.get('pending'),8);self.assertFalse(n.saves)
        for _ in range(16):n.clock(1000)
        n.pump();self.assertEqual(len(n.saves),1)
        # Native write time belongs between visible notices, but is excluded
        # from the next active minute by the save wrapper's reset.
        p=self.machine(config={'IntervalMinutes':'1'})
        original=p.callbacks[p.base+b.R['save_original']]
        def slow_save():
            p.now+=30000
            original()
        p.callbacks[p.base+b.R['save_original']]=slow_save
        p.clock(0);notices=[]
        for _ in range(124):
            before=len(p.notices)
            p.clock(1000);p.pump()
            if len(p.notices)!=before:notices.append(p.now)
        self.assertEqual(len(notices),2)
        self.assertEqual(notices[1]-notices[0],91000)

    def test_session_reset_and_native_return_is_not_success(self):
        m = self.machine(config={'ShowNotification':'false','MaxAutoSaves':'1'})
        m.event('pickup_hook')
        m.run(m.base+b.R['load_hook'],end=0x510bc7)
        self.assertEqual(m.get('pending'),0); m.mature(); self.assertFalse(m.saves)
        for value in [0,1,0x8003001d]:
            m.save_eax=value; m.event('delivery_hook'); m.mature()
        self.assertEqual([s[0] for s in m.saves],['autosave_1']*3)
        self.assertFalse(m.notices)
        self.assertEqual(m.get('busy'),0)

    def test_patch_failure_disables_event_requests(self):
        m = Machine(); m.fail_protect=3; m.install()
        self.assertEqual(m.status['Result'],'PatchFailed')
        m.event('pickup_hook'); m.mature(); self.assertFalse(m.saves)

    def test_world_load_and_player_replacement_discard_old_requests(self):
        m = self.machine(); m.event('pickup_hook')
        m.run(m.base+b.R['world_load_hook'],end=0x4835d6)
        self.assertEqual(m.get('pending'),0)
        self.assertEqual(m.u.reg_read(UC_X86_REG_ESP),SP-0x258)
        m.event('delivery_hook')
        replacement = HEAP+0x60000
        m.w(replacement+0x5c,1); m.w(m.vehicle+0x509c,replacement)
        m.clock(); self.assertEqual(m.get('pending'),0)

    def test_hook_machine_context_survives_configuration_and_native_calls(self):
        from keystone import Ks, KS_ARCH_X86, KS_MODE_32
        for ready in [False,True]:
            with self.subTest(initialized=ready):
                m = Machine()
                m.run(m.base+b.R['entry'],[m.base,1,0])
                if ready:
                    m.pump(); m.event('pickup_hook')
                    for _ in range(5): m.clock()
                    previous=m.callbacks[m.base+b.R['save_original']]
                    def native_fp_clobber():
                        self.assertEqual(m.u.reg_read(UC_X86_REG_FPTAG),0xffff)
                        m.u.reg_write(UC_X86_REG_XMM0,0)
                        previous()
                    m.callbacks[m.base+b.R['save_original']]=native_fp_clobber
                scratch=API+0x900
                m.u.mem_write(scratch,bytes(Ks(KS_ARCH_X86,KS_MODE_32).asm('fninit; fldpi; fld1; ret')[0]))
                m.run(scratch)
                regs=[UC_X86_REG_EAX,UC_X86_REG_EDX,UC_X86_REG_EBX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP]
                for i,reg in enumerate(regs): m.u.reg_write(reg,0x11223300+i)
                m.u.reg_write(UC_X86_REG_XMM0,0x112233445566778899aabbccddeeff00)
                before_fp=[m.u.reg_read(r) for r in [UC_X86_REG_FPCW,UC_X86_REG_FPSW,UC_X86_REG_FPTAG,UC_X86_REG_FP0,UC_X86_REG_FP1,UC_X86_REG_XMM0]]
                before_int=[m.u.reg_read(r) for r in regs]
                m.u.reg_write(UC_X86_REG_EFLAGS,0x647)  # include DF, CF and ZF
                m.pump()
                self.assertEqual([m.u.reg_read(r) for r in regs],before_int)
                self.assertEqual([m.u.reg_read(r) for r in [UC_X86_REG_FPCW,UC_X86_REG_FPSW,UC_X86_REG_FPTAG,UC_X86_REG_FP0,UC_X86_REG_FP1,UC_X86_REG_XMM0]],before_fp)
                self.assertEqual(m.u.reg_read(UC_X86_REG_EFLAGS),0x647)
                self.assertEqual(m.u.reg_read(UC_X86_REG_ECX),0x6d1db8)
                self.assertEqual(m.u.reg_read(UC_X86_REG_ESP),SP-4)
                self.assertEqual(m.r(SP-4),0x1d)

    def test_patched_race_call_preserves_real_caller_stack(self):
        m = self.machine()
        m.w(0x68d164,0); m.w(0x68d188,0)
        m.w(0x68a980,HEAP); m.w(0x68a984,HEAP+4)
        m.w(m.player+0x60,0x4000)
        m.w(SP,m.player)
        m.u.reg_write(UC_X86_REG_ESP,SP)
        m.u.emu_start(0x5701ea,0x5701ef,count=10000)
        self.assertEqual(m.u.reg_read(UC_X86_REG_EIP),0x5701ef)
        self.assertEqual(m.u.reg_read(UC_X86_REG_ESP),SP)
        self.assertEqual(m.r(SP),m.player)
        self.assertEqual(m.get('pending'),4)

    def test_race_original_trampoline_replays_native_prologue(self):
        m=self.machine()
        del m.callbacks[m.base+b.R['race_original']]
        old_ebp=HEAP+0x70000
        m.run(m.base+b.R['race_original'],[m.player],end=0x426b06,
              regs={UC_X86_REG_EBP:old_ebp})
        frame=m.u.reg_read(UC_X86_REG_EBP)
        self.assertEqual(frame,SP-4)
        self.assertEqual(m.r(frame),old_ebp)
        self.assertEqual(m.r(frame+8),m.player)
        self.assertEqual(m.u.reg_read(UC_X86_REG_ESP),(SP-4)&~7)

    def test_real_steam_achievement_wrapper_remains_in_race_call_chain(self):
        import hashlib
        path=b.exe_profiles.input_file('ht2ach.dll')
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         '25a13c1d33bd4d6e3a85c48f70a79c42bf67a53ca26f50ff667097e771b05ca0')
        for base in [0x16000000,0x70690000]:
            for win in [True,False]:
                with self.subTest(base=base,win=win):
                    m=Machine()
                    module=pefile.PE(str(path));module.relocate_image(base)
                    m.u.mem_map(base,0x40000);m.u.mem_write(base,module.get_memory_mapped_image())
                    m.w(base+0x308c8,0x426b00)
                    # This is the actual runtime call redirection observed in
                    # king.exe. AutoSave must neither replace nor whitelist it.
                    redirect=b'\xe8'+P(base+0x81c0-(0x5701ea+5))
                    m.u.mem_write(0x5701ea,redirect)
                    trace=[]
                    def achievement_callback():
                        before=m.args(2)[0]
                        trace.append('achievement_before' if before else 'achievement_after')
                        if not before:
                            self.assertEqual(m.get('pending'),4 if win else 0)
                            self.assertFalse(m.saves)
                        m.ret(0,8)
                    original=m.callbacks[m.base+b.R['race_original']]
                    def finish():
                        trace.append('native_finish');original()
                    m.callbacks[base+0x8180]=achievement_callback
                    m.callbacks[m.base+b.R['race_original']]=finish
                    m.install()
                    self.assertEqual(m.status['Result'],READY_STATUS)
                    self.assertEqual(bytes(m.u.mem_read(0x5701ea,5)),redirect)
                    m.w(0x68d164,0 if win else 1);m.w(0x68d188,0)
                    m.w(0x68a980,HEAP);m.w(0x68a984,HEAP+4)
                    m.w(m.player+0x60,0x4000)
                    m.w(SP,m.player);m.u.reg_write(UC_X86_REG_ESP,SP)
                    m.u.emu_start(0x5701ea,0x5701ef,count=10000)
                    self.assertEqual(m.u.reg_read(UC_X86_REG_EIP),0x5701ef)
                    self.assertEqual(m.u.reg_read(UC_X86_REG_ESP),SP)
                    self.assertEqual(trace,['achievement_before','native_finish','achievement_after'])
                    self.assertEqual(m.race_calls,1)
                    m.mature();self.assertEqual(len(m.saves),int(win))

    def test_real_native_save_wrapper_and_relocated_trampoline(self):
        for base in [BASE,0x18000000]:
            with self.subTest(base=base):
                m = self.machine(base=base,config={'ShowNotification':'false'})
                del m.callbacks[base+b.R['save_original']]
                trace = []
                root,saves,slot = HEAP+0x50000,HEAP+0x52000,HEAP+0x54000
                def com(obj,methods):
                    m.w(obj,obj+0x100)
                    for i,(offset,callback) in enumerate(methods.items()):
                        address = API+0x300+len(m.callbacks)*4
                        m.w(obj+0x100+offset,address)
                        m.callbacks[address]=callback
                def open_profile():
                    self.assertEqual(m.args(2),[m.profile+0x278,2])
                    trace.append('open'); m.ret(root,8)
                def open_saves():
                    a=m.args(7); self.assertEqual(a[3],0x11)
                    m.w(a[6],saves); m.ret(0,28)
                def create_slot():
                    a=m.args(6); self.assertEqual(a[2],0x1011)
                    self.assertEqual(m.string(a[1]),'autosave_1')
                    trace.append('slot'); m.w(a[5],slot); m.ret(0,24)
                def release(): trace.append('release'); m.ret(73,4)
                com(root,{0x18:open_saves,8:release})
                def rotate_delete():
                    self.assertEqual(m.wide_string(m.args(2)[1]),'autosave_3')
                    trace.append('rotate_delete');m.ret(0x80030002,8)
                def rotate_rename():
                    trace.append('rotate_rename');m.ret(0x80030002,12)
                com(saves,{0x14:create_slot,8:release,0x30:rotate_delete,0x34:rotate_rename})
                com(slot,{8:release})
                m.callbacks[0x4d90c0] = lambda: (trace.append('prepare'),m.ret())
                m.callbacks[0x51bfa0] = open_profile
                m.callbacks[0x50bc90] = lambda: m.ret(m.args(1)[0])
                m.callbacks[0x4833a0] = lambda: (trace.append('world'),m.ret())
                m.callbacks[0x51d6d0] = lambda: (trace.append(('metadata',m.args(2)[1])),m.ret())
                selected=b'UNTOUCHED_MANUAL_SLOT\0'
                m.u.mem_write(0x6f2d18,selected)
                m.event('delivery_hook'); m.mature()
                self.assertEqual(trace,['open','rotate_delete','rotate_rename','rotate_rename',
                                        'release','release','prepare','open','slot','world',
                                        ('metadata',0),'release','release','release'])
                self.assertEqual(bytes(m.u.mem_read(0x6f2d18,len(selected))),selected)
                self.assertEqual(m.get('save_count'),1)
                self.assertEqual(m.get('busy'),0)

    def test_native_first_place_prize_branch(self):
        from keystone import Ks, KS_ARCH_X86, KS_MODE_32
        for place,participants,expected in [(0,True,5000),(1,True,0),(0,False,0)]:
            with self.subTest(place=place,participants=participants):
                m = self.machine()
                frame = HEAP+0x70000
                m.w(frame+8,m.player)
                m.w(0x68d164,place); m.w(0x68d188,0)
                m.w(0x68a980,HEAP); m.w(0x68a984,HEAP+(4 if participants else 0))
                m.u.mem_write(m.player+0x88,struct.pack('<d',100.0))
                m.u.mem_write(SP+0x20,struct.pack('<d',360.0))
                # Native first-place branch calls a by-value constructor and
                # award bookkeeping; no stub touches the actual +0x88 balance.
                m.callbacks[0x41d300] = lambda: m.ret(m.u.reg_read(UC_X86_REG_ECX),4)
                m.callbacks[0x4774e0] = lambda: m.ret()
                m.u.mem_write(0x61d830,bytes(Ks(KS_ARCH_X86,KS_MODE_32).asm('fstp st(0); mov eax,1; ret')[0]))
                m.u.reg_write(UC_X86_REG_ESP,SP)
                m.u.reg_write(UC_X86_REG_EBP,frame)
                m.u.reg_write(UC_X86_REG_EAX,m.player)
                m.u.reg_write(UC_X86_REG_EBX,0)
                m.u.emu_start(0x426c77,0x426d71,count=10000)
                self.assertEqual(m.u.reg_read(UC_X86_REG_EIP),0x426d71)
                balance=struct.unpack('<d',m.u.mem_read(m.player+0x88,8))[0]
                self.assertEqual(balance,100.0+expected)


if __name__=='__main__': unittest.main(verbosity=2)
