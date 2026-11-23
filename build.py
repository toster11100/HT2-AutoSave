"""Three-profile AutoSave ASI. Uses the existing Keystone/PE toolchain.

Never installs outputs. No game/save file is written by this builder.
"""
from pathlib import Path
import hashlib
import json
import re
import profiles as exe_profiles
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from pe_builder import make_pe
VERSION = '1.1.0-experimental'
COMPAT_VERSION = '1.1.1-rc.2'
RELEASE_VERSION = '1.1.1'
EXE = exe_profiles.reference('SO')
SHA = '31fbd1dbbe7706183f09a3688482791255db2bfb557c02675374b96796ce2ebd'
RDATA, IDATA, DATA, RELOC = 0x30000, 0x38000, 0x39000, 0x3c000
R = dict(entry=0x1000, init=0x1400, patch=0x2100, active=0x2300,
         request=0x2600, clock=0x2800, tick=0x2c00, reset=0x3000,
         parser=0x3200, language=0x3600, save=0x4000, save_original=0x4200,
         pump_hook=0x4400, clock_hook=0x4600, pickup_hook=0x4800,
         delivery_hook=0x4a00, present_hook=0x4c00, race_hook=0x4e00, race_original=0x5000,
         load_hook=0x5200, world_load_hook=0x5400, hex_address=0x5800,
         vehicle_purchase_hook=0x5a00, driver_hire_hook=0x5c00,
         rotate=0x6000, wide_slot=0x6500, rotation_failed=0x6700, ini_file=0x7000)
F = {name: DATA + i*4 for i, name in enumerate((
    'Enabled', 'OnCargoPickup', 'OnCargoDelivery', 'OnRaceVictory',
    'IntervalEnabled', 'IntervalMinutes', 'MaxAutoSaves', 'ShowNotification',
    'ready', 'pending', 'elapsed', 'last_tick', 'prev_active', 'age', 'busy',
    'slot', 'save_count', 'last_reason', 'player', 'epoch', 'in_tick', 'module',
    'language', 'scratch', 'pinned', 'conflict_address',
    'OnVehiclePurchase', 'OnDriverHire', 'rotation_error',
    'ini_state','ini_error','ini_readable','io_count'))}
INI, STATUS, BUFFER, SLOTNAME, TRUCKINI = [DATA+x for x in (0x100, 0x300, 0x500, 0x600, 0x700)]
WIDE_SOURCE, WIDE_TARGET = DATA+0x800, DATA+0x840
CONFIG = [('Enabled', 1, 1), ('OnCargoPickup', 1, 1), ('OnCargoDelivery', 1, 1),
          ('OnRaceVictory', 1, 1), ('IntervalEnabled', 1, 1),
          ('IntervalMinutes', 10, 1440), ('MaxAutoSaves', 3, 99), ('ShowNotification', 1, 1),
          ('OnVehiclePurchase', 1, 1), ('OnDriverHire', 1, 1)]
APIS = ['GetModuleHandleA', 'GetModuleFileNameA', 'GetModuleHandleExA',
        'VirtualProtect', 'FlushInstructionCache', 'GetPrivateProfileStringA',
        'WritePrivateProfileStringA', 'GetTickCount', 'GetCurrentProcessId', 'GetProcAddress',
        'CreateFileA','ReadFile','WriteFile','CloseHandle','GetLastError',
        'GetForegroundWindow', 'GetWindowThreadProcessId']
KERNEL_COUNT=len(APIS)-2
IAT = {name: IDATA + 0x200+i*4 for i, name in enumerate(APIS)}
HOOKS = [('pump_hook', 0x598145, 7), ('clock_hook', 0x4e1087, 5),
         ('pickup_hook', 0x444d77, 7), ('delivery_hook', 0x44456d, 9),
         ('present_hook', 0x443769, 6), ('race_hook', 0x426b00, 6),
         ('load_hook', 0x510bc0, 7), ('save', 0x51d8f0, 9),
         ('world_load_hook', 0x4835d0, 6),
         ('vehicle_purchase_hook', 0x56ff86, 10), ('driver_hire_hook', 0x476f0b, 6)]
GUARDS = [(va, length) for _, va, length in HOOKS] + [
    (0x51da80, 0x25), (0x51bfa0, 0xff), (0x4d90c0, 0x2af),
    (0x4833a0, 0x230), (0x51d6d0, 0x220), (0x568f60, 0x2d),
    (0x56ae60, 21), (0x5699b0, 246), (0x426b00, 0x41a),
    (0x4176d4, 0x18), (0x444256, 0x63), (0x44413f, 0xa8),
    (0x444c3a, 0x32), (0x570123, 0xc7), (0x5701ef, 0x10), (0x50c150, 0x70),
    (0x476bc0, 0x3a8), (0x56fe6c, 0x9b), (0x56ff0c, 0x7a), (0x50bc90, 0x21),
    (0x51d8f0,0xe7), (0x56ce40,0x40), (0x61cca9,0x30)]

def u32(value): return struct.pack('<I', value & 0xffffffff)
def mem(name): return f'dword ptr [ebx+{F[name]}]'
BASE = 'call base_here; base_here: pop ebx; sub ebx,base_here; cld;'


def _profile_blob(release=False, profile='SO', bank=0, data_offset=0, compat_version=None):
    R={key:value+bank for key,value in globals()['R'].items()}
    R['entry']+=0x100
    compat_rc = compat_version is not None
    if compat_rc:
        R['trailers_guard'] = bank+0x7800
    ga=lambda va:exe_profiles.address(profile,va)
    version = compat_version if compat_rc else ('1.1.0' if release else VERSION)
    ready_status = 'Ready' if release or compat_rc else 'ExperimentalReady'
    module_name = 'HT2_AutoSave.asi' if release or compat_rc else 'HT2_AutoSave_Experimental.asi'
    raw = exe_profiles.reference(profile).read_bytes()
    pe = pefile.PE(data=raw)
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    data = bytearray()
    def blob(value):
        address = RDATA+data_offset+len(data)
        data.extend(value)
        return address
    def string(value, encoding='ascii'): return blob(value.encode(encoding)+b'\0')
    strings = {s: string(s) for s in ['AutoSave', 'Result', 'Version', 'ConflictAddress', version,
        ready_status, 'Disabled', 'SignatureConflict', 'PatchFailed',
        'RotationFailed', 'RotationError', 'IniStatus','IniError','Profile',
        'plugins\\HT2_AutoSave.ini', 'plugins\\HT2_AutoSave_Status.ini', 'TRUCK.INI',
        'ENV', 'langv', 'rus', '', 'true', 'false', 'yes', 'no', 'on', 'off',
        'autosave_%u', 'steam_api.dll', 'SteamAPI_SteamApps_v009',
        'SteamAPI_SteamApps_v008', 'SteamAPI_ISteamApps_GetCurrentGameLanguage']}
    config = [(name, string(name), string(str(default)), maximum, default)
              for name, default, maximum in CONFIG]
    messages = [string(s, 'cp1251') for s in (
        'AUTOSAVE', 'АВТОСОХРАНЕНИЕ', 'SAUVEGARDE AUTO', 'AUTOMATISCHES SPEICHERN', 'GUARDADO AUTOMATICO')]
    message_table = blob(b''.join(u32(s) for s in messages))
    hex_digits = string('0123456789ABCDEF')
    wide_prefix = blob('autosave_'.encode('utf-16le'))
    profile_label = exe_profiles.canonical_profile(profile) if compat_rc else exe_profiles.PROFILES[profile]['name']
    profile_name=string(profile_label)
    ini_states=[string(s) for s in ['Existing','Created','ReadFailed','CreateFailed','WriteFailed']]
    ini_state_table=blob(b''.join(u32(v) for v in ini_states))
    default_ini=('[AutoSave]\r\n'+''.join(f'{name} = {"true" if maximum==1 and default else "false" if maximum==1 else default}\r\n'
                for name,default,maximum in CONFIG)).encode('ascii')
    ini_payload=blob(default_ini)
    ranges = GUARDS
    signatures = [(va, blob(pe.get_data(ga(va)-0x400000, n)), n) for va, n in ranges]
    for _, va, n in HOOKS:
        instructions = list(md.disasm(pe.get_data(ga(va)-0x400000, n), ga(va)))
        assert sum(i.size for i in instructions) == n, hex(va)

    imports = bytearray(0x800)
    name_position = 0x300
    for lib_index, (lib, names) in enumerate([
            ('KERNEL32.dll', APIS[:KERNEL_COUNT]), ('USER32.dll', APIS[KERNEL_COUNT:])]):
        dll_offset = 0x100+lib_index*0x20
        imports[dll_offset:dll_offset+len(lib)+1] = lib.encode()+b'\0'
        first = APIS.index(names[0])
        ilt = 0x140+lib_index*0x80
        struct.pack_into('<IIIII', imports, lib_index*20,
                         IDATA+ilt, 0, 0, IDATA+dll_offset, IAT[names[0]])
        for i, name in enumerate(names):
            encoded = b'\0\0'+name.encode()+b'\0'
            imports[name_position:name_position+len(encoded)] = encoded
            struct.pack_into('<I', imports, ilt+i*4, IDATA+name_position)
            struct.pack_into('<I', imports, 0x200+(first+i)*4, IDATA+name_position)
            name_position += (len(encoded)+1)&~1
    # Each import descriptor must have a terminating null thunk.
    # Insert a gap between the two IAT arrays (their former contiguous boundary
    # would be interpreted as kernel imports). Give USER32 a separate IAT area.
    for i, name in enumerate(APIS[KERNEL_COUNT:]):
        IAT[name] = IDATA+0x2c0+i*4
        value = struct.unpack_from('<I', imports, 0x200+(KERNEL_COUNT+i)*4)[0]
        struct.pack_into('<I', imports, 0x2c0+i*4, value)
        struct.pack_into('<I', imports, 0x200+(KERNEL_COUNT+i)*4, 0)
    struct.pack_into('<I', imports, 20+16, IAT[APIS[KERNEL_COUNT]])
    if compat_rc:
        # Keep the extra descriptor's name and lookup table outside the
        # KERNEL32/USER32 entries used by the published build.
        crypto_name = 0x110
        crypto_ilt = 0x1e0
        crypto_iat = IDATA+0x2e0
        struct.pack_into('<IIIII', imports, 40, IDATA+crypto_ilt, 0, 0, IDATA+crypto_name, crypto_iat)
        dll_name = b'CRYPT32.dll\0'
        crypto_import = b'\0\0CryptHashCertificate2\0'
        imports[crypto_name:crypto_name+len(dll_name)] = dll_name
        imports[0x700:0x700+len(crypto_import)] = crypto_import
        struct.pack_into('<I', imports, crypto_ilt, IDATA+0x700)
        struct.pack_into('<I', imports, 0x2e0, IDATA+0x700)

    chunks = {}
    if compat_rc:
        # HT2 AI Trailers 1.3.6 replaces just the displacement of a CALL in
        # the guarded save preparation routine. Validate the relocated wrapper
        # in memory and its selected native callee before accepting that CALL.
        call_site = 0x51d879
        call_va = ga(0x51d6d0) + (call_site-0x51d6d0)
        native = call_va + 5 + struct.unpack('<i', pe.get_data(call_va-0x400000+1,4))[0]
        table_rva = {'SO':0x10240, 'FR':0x100e4, 'MC':0x1039c}[profile]
        native_addr = blob(u32(native))
        kernel_name = string('kernel32.dll')
        module_query = string('VirtualQuery')
        sha256_name = blob('SHA256\0'.encode('utf-16le'))
        wrapper_hash = blob(bytes.fromhex('82b2a55ee4bbb08faafc6c681e33f70ca335eba22d51802d7b85598ca69be168'))
        wrapper_relocs = (0xc,0x32,0x64,0xe0,0x10e,0x16b,0x1a2,0x1a9,0x1b4,
                          0x1c7,0x1dd,0x1fa,0x212,0x244,0x2c0,0x2cc,0x2d6,
                          0x303,0x318,0x328,0x331,0x347,0x378,0x3de,0x3e7,0x3f2,0x3f8)
        normalize = ''.join(f'sub dword ptr [edi+{offset}],eax;' for offset in wrapper_relocs)
        chunks['trailers_guard'] = f'''
            push ebp; mov ebp,esp; sub esp,0x440; push esi; push edi;
            lea eax,[ebp-4]; push eax; push edx; push 6;
            mov [ebp-8],edx; call dword ptr [ebx+{IAT['GetModuleHandleExA']}];
            test eax,eax; jz trailers_bad;
            mov edi,[ebp-4]; lea ecx,[edi+0x8f90]; cmp ecx,[ebp-8]; jne trailers_bad;
            lea eax,[ebx+{kernel_name}]; push eax; call dword ptr [ebx+{IAT['GetModuleHandleA']}];
            test eax,eax; jz trailers_bad;
            lea ecx,[ebx+{module_query}]; push ecx; push eax;
            call dword ptr [ebx+{IAT['GetProcAddress']}]; test eax,eax; jz trailers_bad;
            mov esi,eax;
            mov ecx,edi; mov edx,0x1000; call trailers_readable; test eax,eax; jz trailers_bad;
            cmp word ptr [edi],0x5a4d; jne trailers_bad;
            mov edx,[edi+0x3c]; cmp edx,0xfac; ja trailers_bad;
            cmp dword ptr [edi+edx],0x4550; jne trailers_bad;
            cmp dword ptr [edi+edx+0x50],0x46000; jne trailers_bad;
            lea ecx,[edi+{table_rva}+0x100]; mov edx,0x38; call trailers_readable; test eax,eax; jz trailers_bad;
            lea ecx,[edi+0x12010]; mov edx,4; call trailers_readable; test eax,eax; jz trailers_bad;
            lea ecx,[edi+{table_rva}]; cmp [edi+0x12010],ecx; jne trailers_bad;
            mov edx,[ebx+{native_addr}]; cmp [ecx+0x100],edx; jne trailers_bad;
            cmp dword ptr [ecx+0x134],0x696ca0; jne trailers_bad;
            lea ecx,[edi+0x398c0]; mov edx,4; call trailers_readable; test eax,eax; jz trailers_bad;
            cmp [edi+0x398c0],esi; jne trailers_bad;
            lea ecx,[edi+0x8f90]; mov edx,0x410; call trailers_readable; test eax,eax; jz trailers_bad;
            lea esi,[edi+0x8f90]; lea edi,[ebp-0x440]; mov ecx,0x410; rep movsb;
            lea edi,[ebp-0x440]; mov eax,[ebp-4]; sub eax,0x10000000;
            {normalize}
            mov dword ptr [ebp-0xc],32;
            lea eax,[ebp-0xc]; push eax; lea eax,[ebp-0x2c]; push eax;
            push 0x410; push edi; push 0; push 0; lea eax,[ebx+{sha256_name}]; push eax;
            call dword ptr [ebx+{crypto_iat}]; test eax,eax; jz trailers_bad;
            cmp dword ptr [ebp-0xc],32; jne trailers_bad;
            lea esi,[ebp-0x2c]; lea edi,[ebx+{wrapper_hash}]; mov ecx,32;
            repe cmpsb; sete al; movzx eax,al; jmp trailers_done;
            trailers_bad: xor eax,eax;
            trailers_done: pop edi; pop esi; mov esp,ebp; pop ebp; ret;
            trailers_readable:
            sub esp,28; lea eax,[ecx+edx]; push eax; lea eax,[esp+4];
            push 28; push eax; push ecx; call esi;
            cmp eax,28; jne trailers_unreadable;
            cmp [esp+8],edi; jne trailers_unreadable;
            cmp dword ptr [esp+20],0x1000; jne trailers_unreadable;
            cmp dword ptr [esp+28],0x1000000; jne trailers_unreadable;
            test dword ptr [esp+24],0x100; jnz trailers_unreadable;
            test dword ptr [esp+24],0xee; jz trailers_unreadable;
            mov eax,[esp+4]; add eax,[esp+16]; jc trailers_unreadable;
            cmp eax,[esp]; setae al; movzx eax,al; add esp,32; ret;
            trailers_unreadable: xor eax,eax; add esp,32; ret;
        '''
    # DllMain: minimal bootstrap only; config and remaining hooks run on game thread.
    s = f'''cmp dword ptr [esp+8],1; jne entry_ok;
        pushfd; pushad; mov ebx,[esp+40]; mov {mem('module')},ebx;
        push 0; call dword ptr [ebx+{IAT['GetModuleHandleA']}];
        cmp eax,0x400000; jne entry_done;
        mov edx,[eax+0x3c]; add edx,eax;
        cmp dword ptr [edx],0x4550; jne entry_done;
        cmp dword ptr [edx+8],{pe.FILE_HEADER.TimeDateStamp}; jne entry_done;
        cmp dword ptr [edx+0x50],{pe.OPTIONAL_HEADER.SizeOfImage}; jne entry_done;
        cld; mov esi,0x598145; lea edi,[ebx+{signatures[0][1]}]; mov ecx,7;
        repe cmpsb; jne entry_done;
        lea eax,[ebx+{F['pinned']}]; push eax; push ebx; push 5;
        call dword ptr [ebx+{IAT['GetModuleHandleExA']}]; test eax,eax; jz entry_done;
        mov ecx,0x598145; mov edx,{R['pump_hook']}; mov esi,7; call {R['patch']};
        test eax,eax; jnz entry_done; mov {mem('ready')},-1;
        entry_done: popad; popfd;
        entry_ok: mov eax,1; ret 12;'''
    chunks['entry'] = s

    # stdcall OS calls; EAX=1 only after protect/write/flush/protection-restore.
    chunks['patch'] = f'''
        push ebp; mov ebp,esp; sub esp,8; push edi; push esi; push edx; push ecx;
        lea eax,[ebp-4]; push eax; push 0x40; push esi; push ecx;
        call dword ptr [ebx+{IAT['VirtualProtect']}]; test eax,eax; jz patch_fail;
        mov ecx,[ebp-24]; mov edx,[ebp-20]; mov esi,[ebp-16];
        lea eax,[ebx+edx]; sub eax,ecx; sub eax,5;
        mov byte ptr [ecx],0xe9; mov [ecx+1],eax;
        lea edi,[ecx+5]; sub esi,5; mov eax,0x90; mov ecx,esi; rep stosb;
        mov ecx,[ebp-24]; mov esi,[ebp-16];
        push esi; push ecx; push -1;
        call dword ptr [ebx+{IAT['FlushInstructionCache']}]; mov [ebp-8],eax;
        lea eax,[ebp-4]; push eax; push dword ptr [ebp-4]; push dword ptr [ebp-16];
        push dword ptr [ebp-24]; call dword ptr [ebx+{IAT['VirtualProtect']}];
        and eax,[ebp-8]; jmp patch_done;
        patch_fail: xor eax,eax;
        patch_done: add esp,8; pop esi; pop edi; mov esp,ebp; pop ebp; ret;
    '''

    # Both callers preserve machine state. EAX=active, ECX=current PlayerId.
    chunks['active'] = f'''
        xor ecx,ecx; cmp {mem('Enabled')},0; je inactive;
        cmp {mem('busy')},0; jne inactive;
        mov eax,[0x696ca0]; test eax,eax; jz inactive;
        cmp eax,[0x696848]; jne inactive;
        test byte ptr [eax+0x10],2; jz inactive;
        cmp dword ptr [0x69689c],0; jne inactive;
        cmp dword ptr [0x6ce4f4],0; jne inactive;
        mov edx,[0x6cec6c]; test edx,edx; jz inactive;
        cmp dword ptr [edx+0x514],0; jne inactive;
        cmp dword ptr [edx+0x524],0; jne inactive;
        mov eax,[edx+0x504]; or eax,[edx+0x508]; or eax,[edx+0x510]; jnz inactive;
        mov eax,[0x6cecd8]; test eax,eax; jz inactive;
        cmp byte ptr [eax+0x278],0; je inactive;
        mov eax,[0x6d2078]; test eax,eax; jz inactive;
        mov eax,[eax+0x268]; test eax,eax; jz inactive;
        mov ecx,[eax+0x509c]; test ecx,ecx; jz inactive;
        cmp ecx,[0x68b990]; je inactive;
        cmp dword ptr [ecx+0x5c],1; jne inactive;
        push ecx; call dword ptr [ebx+{IAT['GetForegroundWindow']}];
        test eax,eax; jz foreground_bad;
        lea edx,[ebx+{F['scratch']}]; push edx; push eax;
        call dword ptr [ebx+{IAT['GetWindowThreadProcessId']}];
        call dword ptr [ebx+{IAT['GetCurrentProcessId']}];
        cmp eax,{mem('scratch')}; jne foreground_bad;
        pop ecx; mov eax,1; ret;
        foreground_bad: pop ecx;
        inactive: xor eax,eax; ret;
    '''
    chunks['reset'] = ''.join(f'mov {mem(k)},0;' for k in
        ('pending','elapsed','last_tick','prev_active','age','player')) + f'inc {mem("epoch")}; ret;'
    chunks['request'] = f'''
        cmp {mem('ready')},1; jne request_done;
        cmp {mem('Enabled')},0; je request_done;
        cmp {mem('busy')},0; jne request_done;
        test ecx,ecx; jz request_done;
        cmp dword ptr [ecx+0x5c],1; jne request_done;
        mov edx,[0x6d2078]; test edx,edx; jz request_done;
        mov edx,[edx+0x268]; test edx,edx; jz request_done;
        cmp ecx,[edx+0x509c]; jne request_done;
        cmp {mem('player')},0; je request_identity;
        cmp ecx,{mem('player')}; je request_identity;
        push eax; push ecx; call {R['reset']}; pop ecx; pop eax;
        request_identity: mov {mem('player')},ecx;
        cmp eax,1; je request_pickup;
        cmp eax,2; je request_delivery;
        cmp eax,4; je request_race;
        cmp eax,16; je request_vehicle;
        cmp eax,32; je request_driver;
        jmp request_done;
        request_pickup: cmp {mem('OnCargoPickup')},0; je request_done; jmp request_enabled;
        request_delivery: cmp {mem('OnCargoDelivery')},0; je request_done; jmp request_enabled;
        request_race: cmp {mem('OnRaceVictory')},0; je request_done; jmp request_enabled;
        request_vehicle: cmp {mem('OnVehiclePurchase')},0; je request_done; jmp request_enabled;
        request_driver: cmp {mem('OnDriverHire')},0; je request_done;
        request_enabled:
        test {mem('pending')},eax; jnz request_done;
        or {mem('pending')},eax; mov {mem('age')},0;
        request_done: ret;
    '''
    # Reason bits: 1 pickup, 2 delivery, 4 victory, 8 interval, 16 purchase, 32 hire.
    chunks['clock'] = f'''
        cmp {mem('ready')},1; jne clock_done;
        call dword ptr [ebx+{IAT['GetTickCount']}]; mov esi,eax;
        sub eax,{mem('last_tick')}; mov edi,eax; mov {mem('last_tick')},esi;
        call {R['active']}; test eax,eax; jz clock_inactive;
        cmp {mem('player')},0; je clock_identity;
        cmp ecx,{mem('player')}; je clock_identity;
        call {R['reset']}; mov {mem('last_tick')},esi;
        clock_identity: mov {mem('player')},ecx;
        cmp {mem('prev_active')},0; je clock_first;
        cmp edi,2000; ja clock_first;
        add {mem('elapsed')},edi;
        cmp {mem('pending')},0; je clock_interval;
        add {mem('age')},edi;
        clock_interval: cmp {mem('IntervalEnabled')},0; je clock_first;
        mov eax,{mem('elapsed')}; cmp eax,{mem('IntervalMinutes')}; jb clock_first;
        or {mem('pending')},8;
        cmp {mem('pending')},8; jne clock_first;
        mov {mem('age')},750;
        clock_first: mov {mem('prev_active')},1; ret;
        clock_inactive: mov {mem('prev_active')},0; mov {mem('age')},0;
        clock_done: ret;
    '''
    # Native call normal return only; no HRESULT/success interpretation.
    chunks['tick'] = f'''
        cmp {mem('ready')},0; jne tick_initialized;
        call {R['init']};
        tick_initialized: cmp {mem('ready')},1; jne tick_done;
        cmp {mem('in_tick')},0; jne tick_done;
        cmp {mem('pending')},0; je tick_done;
        cmp {mem('age')},750; jb tick_done;
        call {R['active']}; test eax,eax; jz tick_done;
        mov {mem('in_tick')},1;
        inc {mem('busy')}; call {R['rotate']}; dec {mem('busy')};
        test eax,eax; js tick_rotation_failed;
        push 1; lea eax,[ebx+{strings['autosave_%u']}]; push eax;
        lea eax,[ebx+{SLOTNAME}]; push eax; mov eax,0x61cca9; call eax; add esp,12;
        mov eax,{mem('pending')}; mov {mem('last_reason')},eax;
        mov {mem('pending')},0; mov {mem('age')},0;
        push 0; lea eax,[ebx+{SLOTNAME}]; push eax;
        mov eax,0x51d8f0; call eax; add esp,8;
        inc {mem('save_count')};
        cmp {mem('ShowNotification')},0; je tick_returned;
        mov eax,{mem('language')}; lea edx,[ebx+{message_table}];
        mov eax,[edx+eax*4]; add eax,ebx; push eax;
        mov eax,0x56ae60; call eax; add esp,4;
        jmp tick_returned;
        tick_rotation_failed: mov {mem('rotation_error')},eax;
        mov {mem('ready')},3; mov {mem('pending')},0; mov {mem('age')},0;
        call {R['rotation_failed']};
        tick_returned: mov {mem('in_tick')},0;
        tick_done: ret;
    '''
    chunks['save'] = f'''
        push ebp; mov ebp,esp; push ebx; {BASE}
        inc {mem('busy')}; push dword ptr [ebp+12]; push dword ptr [ebp+8];
        call {R['save_original']}; add esp,8;
        dec {mem('busy')}; mov {mem('elapsed')},0; mov {mem('prev_active')},0;
        mov {mem('age')},0; mov {mem('pending')},0;
        pop ebx; pop ebp; ret;
    '''
    chunks['save_original'] = 'sub esp,8; push esi; mov eax,0x4d90c0; call eax; push 0x51d8f9; ret;'

    # Reuse native profile opening, in the game thread, with no live child slot.
    # Release container and root BEFORE native save opens the same profile.
    # Missing autoslots are normal. Any other COM error stops the operation;
    # this is not a transaction and no failed native write is retried.
    chunks['rotate'] = f'''
        push esi; push edi; push ebp; sub esp,12;
        mov dword ptr [esp],0; mov dword ptr [esp+4],0; mov dword ptr [esp+8],0;
        cmp {mem('MaxAutoSaves')},1; jbe rotate_release;
        mov ecx,[0x6cecd8]; test ecx,ecx; jz rotate_invalid;
        push 2; lea eax,[ecx+0x278]; push eax;
        mov eax,0x51bfa0; call eax; mov [esp],eax;
        test eax,eax; jz rotate_invalid;
        mov ebp,eax;
        push 0x67683c; mov eax,0x50bc90; call eax; add esp,4;
        lea edx,[esp+4]; push edx; push 0; push 0; push 0x11; push 0; push eax; push ebp;
        mov edx,[ebp]; call dword ptr [edx+0x18];
        test eax,eax; js rotate_error;
        mov esi,[esp+4]; test esi,esi; jz rotate_invalid;
        mov eax,{mem('MaxAutoSaves')}; lea edi,[ebx+{WIDE_SOURCE}]; call {R['wide_slot']};
        lea eax,[ebx+{WIDE_SOURCE}]; push eax; push esi;
        mov edx,[esi]; call dword ptr [edx+0x30];
        test eax,eax; jns rotate_start;
        cmp eax,0x80030002; jne rotate_error;
        rotate_start: mov ebp,{mem('MaxAutoSaves')}; dec ebp;
        rotate_next: mov eax,ebp; lea edi,[ebx+{WIDE_SOURCE}]; call {R['wide_slot']};
        lea eax,[ebp+1]; lea edi,[ebx+{WIDE_TARGET}]; call {R['wide_slot']};
        lea eax,[ebx+{WIDE_TARGET}]; push eax;
        lea eax,[ebx+{WIDE_SOURCE}]; push eax; push esi;
        mov edx,[esi]; call dword ptr [edx+0x34];
        test eax,eax; jns rotate_advance;
        cmp eax,0x80030002; jne rotate_error;
        rotate_advance: dec ebp; jnz rotate_next; jmp rotate_release;
        rotate_invalid: mov eax,0x80004005;
        rotate_error: mov [esp+8],eax;
        rotate_release: mov eax,[esp+4]; test eax,eax; jz rotate_root;
        push eax; mov edx,[eax]; call dword ptr [edx+8];
        rotate_root: mov eax,[esp]; test eax,eax; jz rotate_return;
        push eax; mov edx,[eax]; call dword ptr [edx+8];
        rotate_return: mov eax,[esp+8]; add esp,12; pop ebp; pop edi; pop esi; ret;
    '''
    # EAX=1..99, EDI=destination (24 bytes); no shared ANSI conversion buffer.
    chunks['wide_slot'] = f'''
        mov edx,eax; lea ecx,[ebx+{wide_prefix}];
        mov eax,[ecx]; mov [edi],eax; mov eax,[ecx+4]; mov [edi+4],eax;
        mov eax,[ecx+8]; mov [edi+8],eax; mov eax,[ecx+12]; mov [edi+12],eax;
        mov ax,[ecx+16]; mov [edi+16],ax;
        add edi,18; mov eax,edx; xor edx,edx; mov ecx,10; div ecx;
        test eax,eax; jz wide_units;
        add eax,48; mov [edi],ax; add edi,2;
        wide_units: add edx,48; mov [edi],dx; mov word ptr [edi+2],0; ret;
    '''
    chunks['rotation_failed'] = f'''
        lea eax,[ebx+{STATUS}]; push eax; lea eax,[ebx+{strings['RotationFailed']}]; push eax;
        lea eax,[ebx+{strings['Result']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        mov eax,{mem('rotation_error')}; call {R['hex_address']};
        lea eax,[ebx+{STATUS}]; push eax; lea eax,[ebx+{BUFFER}]; push eax;
        lea eax,[ebx+{strings['RotationError']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}]; ret;
    '''
    # CREATE_NEW never overwrites an existing INI. Validate readability before
    # calling the native Win32 INI parser, which otherwise hides read errors.
    chunks['ini_file'] = f'''
        push esi; push edi; xor edi,edi;
        mov {mem('ini_readable')},0; mov {mem('ini_error')},0;
        ini_open: push 0; push 0x80; push 3; push 0; push 3; push 0x80000000;
        lea eax,[ebx+{INI}]; push eax; call dword ptr [ebx+{IAT['CreateFileA']}];
        cmp eax,-1; jne ini_read;
        call dword ptr [ebx+{IAT['GetLastError']}];
        cmp eax,2; jne ini_read_error; test edi,edi; jnz ini_read_error;
        push 0; push 0x80; push 1; push 0; push 3; push 0x40000000;
        lea eax,[ebx+{INI}]; push eax; call dword ptr [ebx+{IAT['CreateFileA']}];
        cmp eax,-1; jne ini_write;
        call dword ptr [ebx+{IAT['GetLastError']}];
        cmp eax,80; je ini_race; cmp eax,183; je ini_race;
        mov {mem('ini_state')},3; jmp ini_no_handle;
        ini_race: inc edi; jmp ini_open;
        ini_write: mov esi,eax; mov {mem('ini_state')},1;
        mov {mem('io_count')},0; push 0; lea eax,[ebx+{F['io_count']}]; push eax;
        push {len(default_ini)}; lea eax,[ebx+{ini_payload}]; push eax; push esi;
        call dword ptr [ebx+{IAT['WriteFile']}]; test eax,eax; jz ini_write_error;
        cmp {mem('io_count')},{len(default_ini)}; je ini_close;
        mov eax,29; jmp ini_write_failed;
        ini_write_error: call dword ptr [ebx+{IAT['GetLastError']}];
        ini_write_failed: mov {mem('ini_state')},4; mov {mem('ini_error')},eax; jmp ini_close;
        ini_read: mov esi,eax; mov {mem('ini_state')},0;
        ini_read_next: mov {mem('io_count')},0;
        push 0; lea eax,[ebx+{F['io_count']}]; push eax; push 4096;
        lea eax,[ebx+{DATA+0x1000}]; push eax; push esi;
        call dword ptr [ebx+{IAT['ReadFile']}]; test eax,eax; jz ini_read_failed;
        cmp {mem('io_count')},0; jne ini_read_next;
        mov {mem('ini_readable')},1; jmp ini_close;
        ini_read_failed: call dword ptr [ebx+{IAT['GetLastError']}];
        mov {mem('ini_state')},2; mov {mem('ini_error')},eax;
        ini_close: push esi; call dword ptr [ebx+{IAT['CloseHandle']}];
        test eax,eax; jnz ini_done;
        call dword ptr [ebx+{IAT['GetLastError']}]; mov {mem('ini_readable')},0;
        mov {mem('ini_state')},2; mov {mem('ini_error')},eax; jmp ini_done;
        ini_read_error: mov {mem('ini_state')},2;
        ini_no_handle: mov {mem('ini_error')},eax;
        ini_done: pop edi; pop esi; ret;
    '''

    # Preserve integer/flags, x87 and SSE, and give native save an empty x87
    # stack even when an intercepted caller has live FP temporaries.
    def guarded(body):
        return f'''pushfd; pushad; {BASE}
            mov eax,esp; sub esp,528; and esp,-16; mov [esp+512],eax;
            fxsave [esp]; fninit;
            {body}; fxrstor [esp]; mov esp,[esp+512]; popad; popfd;'''
    chunks['pump_hook'] = guarded(f'call {R["tick"]}') + 'push 0x1d; mov ecx,0x6d1db8; push 0x59814c; ret;'
    # Original callee overwrites EAX at its first instruction.
    chunks['clock_hook'] = 'mov eax,0x56ce40; call eax;' + guarded(f'call {R["clock"]}') + 'push 0x4e108c; ret;'
    event = lambda bit: f'mov ecx,[ebp+8]; mov eax,{bit}; call {R["request"]};'
    chunks['pickup_hook'] = guarded('mov eax,[ebp+0x18]; cmp dword ptr [eax],0; jl event_done;' + event(1) + 'event_done:') + 'lea edx,[esp+0x128]; push 0x444d7e; ret;'
    chunks['delivery_hook'] = guarded('mov eax,[esp+512]; mov eax,[eax+12]; cmp byte ptr [eax+0x17],0; je event_done;' + event(2) + 'event_done:') + 'mov eax,[ebp+0x18]; mov dword ptr [eax],-1; push 0x444576; ret;'
    chunks['present_hook'] = guarded('mov eax,[ebp+0x10]; cmp dword ptr [eax],0; jl event_done;' + event(1) + 'event_done:') + 'mov esi,[0x71e814]; push 0x44376f; ret;'
    chunks['race_hook'] = f'''
        push ebp; mov ebp,esp; push ebx; push esi; push edi; {BASE}
        xor edi,edi; mov esi,[ebp+8];
        test dword ptr [esi+0x60],0x4000; jz race_call;
        cmp dword ptr [0x68d164],0; jne race_call;
        cmp dword ptr [0x68d188],0; jne race_call;
        mov eax,[0x68a980]; cmp eax,[0x68a984]; je race_call;
        mov edi,1;
        race_call: push esi; call {R['race_original']}; add esp,4;
        pushfd; pushad;
        test edi,edi; jz race_done;
        test dword ptr [esi+0x60],0x4000; jnz race_done;
        mov ecx,esi; mov eax,4; call {R['request']};
        race_done: popad; popfd; pop edi; pop esi; pop ebx; pop ebp; ret;
    '''
    chunks['race_original'] = 'push ebp; mov ebp,esp; and esp,-8; push 0x426b06; ret;'
    chunks['load_hook'] = guarded(f'call {R["reset"]}') + 'push -1; push 0x646196; push 0x510bc7; ret;'
    chunks['world_load_hook'] = guarded(f'call {R["reset"]}') + 'sub esp,0x258; push 0x4835d6; ret;'
    # Observe only completed transaction branches. No action, money setter or
    # ownership mutation is called by these hooks. The native caller's locals
    # are read through the saved original ESP (pushad slot is original ESP-4).
    chunks['vehicle_purchase_hook'] = guarded(f'''
        mov eax,[esp+512]; mov eax,[eax+12]; mov ecx,[eax+0x18];
        mov eax,16; call {R['request']};
    ''') + 'pop edi; pop esi; pop ebp; pop ebx; add esp,0x150; push 0x56ff90; ret;'
    chunks['driver_hire_hook'] = guarded(f'''
        mov eax,[esp+512]; mov eax,[eax+12];
        mov ecx,[eax+0x40]; mov edx,[eax+0x44];
        test edx,edx; jz hire_event_done;
        cmp [edx+0xb0],ecx; jne hire_event_done;
        mov eax,32; call {R['request']};
        hire_event_done:;
    ''') + 'xor eax,eax; mov ecx,[esp+0x2c]; push 0x476f11; ret;'
    chunks['hex_address'] = f'''
        lea edi,[ebx+{BUFFER}]; mov edx,8;
        hex_next: rol eax,4; mov ecx,eax; and ecx,15;
        mov cl,[ebx+{hex_digits}+ecx]; mov [edi],cl; inc edi;
        dec edx; jnz hex_next; mov byte ptr [edi],0; ret;
    '''

    # Parser: ESI string, EDX max, EDI default. ASCII case folding, whitespace,
    # true/false/yes/no/on/off or 0/1; bounded positive integer otherwise.
    chunks['parser'] = f'''
        parse_space: cmp byte ptr [esi],32; je skip_space;
        cmp byte ptr [esi],9; jne parse_start;
        skip_space: inc esi; jmp parse_space;
        parse_start: mov ebp,esi;
        parse_scan: mov al,[esi]; test al,al; jz parse_trim;
        cmp al,65; jb parse_next; cmp al,90; ja parse_next; or byte ptr [esi],32;
        parse_next: inc esi; jmp parse_scan;
        parse_trim: cmp esi,ebp; je parse_default;
        cmp byte ptr [esi-1],32; je trim_one; cmp byte ptr [esi-1],9; jne parse_token;
        trim_one: dec esi; mov byte ptr [esi],0; jmp parse_trim;
        parse_token: mov esi,ebp; cmp edx,1; jne parse_number;
    '''
    for token, value in [('true',1),('false',0),('yes',1),('no',0),('on',1),('off',0)]:
        checks = ';'.join(f'cmp byte ptr [esi+{i}],{v}; jne token_{token}_next' for i,v in enumerate(token.encode()+b'\0'))
        chunks['parser'] += f'{checks}; mov eax,{value}; ret; token_{token}_next:;'
    chunks['parser'] += '''
        parse_number: xor eax,eax; xor ecx,ecx;
        parse_digit: movzx ebp,byte ptr [esi]; test ebp,ebp; jz parse_finish;
        sub ebp,48; cmp ebp,9; ja parse_default;
        cmp eax,429496729; ja parse_default;
        imul eax,eax,10; add eax,ebp; jc parse_default;
        cmp eax,edx; ja parse_default; inc ecx; inc esi; jmp parse_digit;
        parse_finish: test ecx,ecx; jz parse_default;
        cmp edx,1; je parse_return; test eax,eax; jz parse_default;
        parse_return: ret;
        parse_default: mov eax,edi; ret;
    '''

    # Steam language first, TRUCK.INI fallback. No required Steam imports.
    chunks['language'] = f'''
        mov {mem('language')},1;
        lea eax,[ebx+{TRUCKINI}]; push eax; push 64; lea eax,[ebx+{BUFFER}]; push eax;
        lea eax,[ebx+{strings['rus']}]; push eax; lea eax,[ebx+{strings['langv']}]; push eax;
        lea eax,[ebx+{strings['ENV']}]; push eax;
        call dword ptr [ebx+{IAT['GetPrivateProfileStringA']}];
        lea esi,[ebx+{BUFFER}]; call language_match;
        lea eax,[ebx+{strings['steam_api.dll']}]; push eax;
        call dword ptr [ebx+{IAT['GetModuleHandleA']}]; test eax,eax; jz language_done;
        mov edi,eax;
    '''
    for steam_getter in ['SteamAPI_SteamApps_v009','SteamAPI_SteamApps_v008']:
        chunks['language'] += f'lea eax,[ebx+{strings[steam_getter]}]; push eax; push edi; call dword ptr [ebx+{IAT["GetProcAddress"]}]; test eax,eax; jnz getter_found;'
    chunks['language'] += f'''
        jmp language_done;
        getter_found: call eax; test eax,eax; jz language_done; mov esi,eax;
        lea eax,[ebx+{strings['SteamAPI_ISteamApps_GetCurrentGameLanguage']}]; push eax; push edi;
        call dword ptr [ebx+{IAT['GetProcAddress']}]; test eax,eax; jz language_done;
        push esi; call eax; add esp,4; test eax,eax; jz language_done;
        mov esi,eax; call language_match;
        language_done: ret;
        language_match: mov eax,[esi]; and eax,0xffffff; or eax,0x202020;
    '''
    for prefix, index in [('eng',0),('rus',1),('fre',2),('fra',2),('ger',3),('deu',3),('spa',4),('esp',4)]:
        chunks['language'] += f'cmp eax,{int.from_bytes(prefix.encode(),"little")}; jne language_next_{prefix}; mov {mem("language")},{index}; ret; language_next_{prefix}:;'
    chunks['language'] += 'ret;'

    # Init invoked by the bootstrap on the gameplay thread, once.
    init = f'mov {mem("ready")},-1;'
    # Keep user settings in the GAME's plugins directory even if the loader
    # resolves the ASI from a Workshop cache or another source directory.
    for target, filename, module in [(INI,'plugins\\HT2_AutoSave.ini',False), (STATUS,'plugins\\HT2_AutoSave_Status.ini',False), (TRUCKINI,'TRUCK.INI',False)]:
        label = f'path_{target:x}'
        init += f'''
            push 500; lea eax,[ebx+{target}]; push eax;
            {'push '+mem('module') if module else 'push 0'};
            call dword ptr [ebx+{IAT['GetModuleFileNameA']}];
            test eax,eax; jz init_return; cmp eax,460; jae init_return;
            lea edx,[ebx+{target}]; mov edi,edx; add edi,eax;
            {label}_scan: cmp edi,edx; jbe init_return;
            dec edi; cmp byte ptr [edi],92; jne {label}_scan;
            inc edi; lea esi,[ebx+{strings[filename]}];
            {label}_copy: lodsb; stosb; test al,al; jnz {label}_copy;
        '''
    init += f'call {R["ini_file"]};'
    for name, key, default_string, maximum, default in config:
        init += f'''
            cmp {mem('ini_readable')},0; je config_{name}_default;
            lea eax,[ebx+{INI}]; push eax; push 64; lea eax,[ebx+{BUFFER}]; push eax;
            lea eax,[ebx+{default_string}]; push eax; lea eax,[ebx+{key}]; push eax;
            lea eax,[ebx+{strings['AutoSave']}]; push eax;
            call dword ptr [ebx+{IAT['GetPrivateProfileStringA']}];
            cmp eax,63; jb config_{name}_parse;
            config_{name}_default: mov eax,{default}; jmp config_{name}_done;
            config_{name}_parse: lea esi,[ebx+{BUFFER}]; mov edi,{default}; mov edx,{maximum};
            push ebp; call {R['parser']}; pop ebp;
            config_{name}_done: {'imul eax,eax,60000;' if name=='IntervalMinutes' else ''}
            mov {mem(name)},eax;
        '''
    init += f'cmp {mem("Enabled")},0; je init_disabled;'
    # Bootstrap is already ours; every other original range must match before mutations.
    for va, signature, n in signatures[1:]:
        if compat_rc and va==0x51d6d0:
            # The original prefix comparison includes the E8 opcode.
            # The suffix and known destination together validate the full range.
            displacement_offset = call_site-va+1
            init += f'''
                mov esi,{va}; lea edi,[ebx+{signature}]; mov ecx,{n};
                repe cmpsb; je trailers_guard_done;
                cmp ecx,{n-displacement_offset-1}; ja init_conflict;
                cmp ecx,{n-displacement_offset-4}; jb init_conflict;
                push esi;
                mov esi,{va}; add esi,{displacement_offset}; mov edx,[esi]; lea edx,[edx+esi+4];
                call {R['trailers_guard']};
                pop esi; test eax,eax; jz init_conflict;
                mov esi,{va}; add esi,{displacement_offset+4};
                lea edi,[ebx+{signature+displacement_offset+4}]; mov ecx,{n-displacement_offset-4};
                repe cmpsb; jne init_conflict;
                trailers_guard_done:;
            '''
        else:
            init += f'mov esi,{va}; lea edi,[ebx+{signature}]; mov ecx,{n}; repe cmpsb; jne init_conflict;'
    init += f'call {R["language"]}; mov {mem("slot")},1;'
    for name, va, n in HOOKS[1:]:
        init += f'mov ecx,{va}; mov edx,{R[name]}; mov esi,{n}; call {R["patch"]}; test eax,eax; jz init_patch_failed;'
    init += f'mov {mem("ready")},1; lea esi,[ebx+{strings[ready_status]}]; jmp init_status;'
    for label, value in [('init_disabled','Disabled'),('init_conflict','SignatureConflict'),('init_patch_failed','PatchFailed')]:
        init += f'{label}: '
        if label=='init_conflict':
            init += f'lea eax,[esi-1]; mov {mem("conflict_address")},eax;'
        init += f'lea esi,[ebx+{strings[value]}]; jmp init_status;'
    init += f'''
        init_status: lea eax,[ebx+{STATUS}]; push eax; push esi;
        lea eax,[ebx+{strings['Result']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        lea eax,[ebx+{STATUS}]; push eax; lea eax,[ebx+{strings[version]}]; push eax;
        lea eax,[ebx+{strings['Version']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        mov eax,{mem('conflict_address')}; call {R['hex_address']};
        lea eax,[ebx+{STATUS}]; push eax; lea eax,[ebx+{BUFFER}]; push eax;
        lea eax,[ebx+{strings['ConflictAddress']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        mov eax,{mem('rotation_error')}; call {R['hex_address']};
        lea eax,[ebx+{STATUS}]; push eax; lea eax,[ebx+{BUFFER}]; push eax;
        lea eax,[ebx+{strings['RotationError']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        lea eax,[ebx+{STATUS}]; push eax; lea eax,[ebx+{profile_name}]; push eax;
        lea eax,[ebx+{strings['Profile']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        mov eax,{mem('ini_state')}; mov eax,[ebx+eax*4+{ini_state_table}]; add eax,ebx;
        lea edx,[ebx+{STATUS}]; push edx; push eax;
        lea eax,[ebx+{strings['IniStatus']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        mov eax,{mem('ini_error')}; call {R['hex_address']};
        lea eax,[ebx+{STATUS}]; push eax; lea eax,[ebx+{BUFFER}]; push eax;
        lea eax,[ebx+{strings['IniError']}]; push eax; lea eax,[ebx+{strings['AutoSave']}]; push eax;
        call dword ptr [ebx+{IAT['WritePrivateProfileStringA']}];
        init_return: ret;
    '''
    chunks['init'] = init

    code = bytearray(0x9000)
    listing = []
    sizes = {}
    for name in sorted(chunks, key=lambda key: R[key]):
        source = re.sub(r'\b(?:0x[0-9a-fA-F]+|[0-9]+)\b',
                        lambda m:str(ga(int(m[0],0) if m[0].startswith('0x') else int(m[0]))),chunks[name])
        binary = bytes(ks.asm(source, addr=R[name])[0])
        following = min([v for v in R.values() if v>R[name]]+[bank+0xa000])
        assert R[name]+len(binary)<=following, (name, len(binary), hex(following-R[name]))
        code[R[name]-bank-0x1000:R[name]-bank-0x1000+len(binary)] = binary
        listing.append(f'; {name} RVA {R[name]:08X}\n'+source.replace(';','\n'))
        sizes[name] = len(binary)
    assert len(data)<0x2800
    meta=dict(name=profile_label,key=profile,
              exe_sha256=hashlib.sha256(raw).hexdigest(),routines=R,sizes=sizes,
              hooks=[dict(routine=k,va=ga(va),length=n,opcode='jmp',expected=pe.get_data(ga(va)-0x400000,n).hex()) for k,va,n in HOOKS],
              guards=[dict(va=ga(va),length=n) for va,n in GUARDS],
              timestamp=pe.FILE_HEADER.TimeDateStamp,image_size=pe.OPTIONAL_HEADER.SizeOfImage)
    return bytes(code),bytes(data),bytes(imports),listing,meta


def build(release=False, compat_rc=False, legacy_release=False):
    if sum((release, compat_rc, legacy_release)) > 1:
        raise ValueError('Choose one build variant.')
    compat_version = RELEASE_VERSION if release else (COMPAT_VERSION if compat_rc else None)
    compat_rc = compat_version is not None
    release = release or legacy_release
    version=compat_version if compat_rc else ('1.1.0' if release else VERSION)
    module_name='HT2_AutoSave.asi' if release or compat_rc else 'HT2_AutoSave_Experimental.asi'
    code=bytearray(RDATA-0x1000);data=bytearray(IDATA-RDATA)
    metadata=[];listing=[]
    for index,key in enumerate(['SO','FR','MC']):
        bank=index*0x10000;offset=index*0x2800
        native,constants,imports,asm,meta=_profile_blob(release,key,bank,offset,compat_version)
        code[bank:bank+len(native)]=native
        data[offset:offset+len(constants)]=constants
        metadata.append(meta);listing.extend(asm)
    dispatch="cmp dword ptr [esp+8],1; jne dispatch_done; push eax; push edx;"
    dispatch+=f"mov edx,[esp+12]; push 0; call dword ptr [edx+{IAT['GetModuleHandleA']}]; cmp eax,0x400000; jne dispatch_restore;"
    dispatch+="mov eax,[0x40003c]; add eax,0x400000; cmp dword ptr [eax],0x4550; jne dispatch_restore;"
    for index,p in enumerate(metadata):
        dispatch+=f"cmp dword ptr [eax+8],{p['timestamp']}; jne dispatch_next_{index}; cmp dword ptr [eax+0x50],{p['image_size']}; jne dispatch_next_{index}; pop edx; pop eax; jmp {p['routines']['entry']}; dispatch_next_{index}:;"
    dispatch+='dispatch_restore: pop edx; pop eax; dispatch_done: mov eax,1; ret 12;'
    binary=bytes(Ks(KS_ARCH_X86,KS_MODE_32).asm(dispatch,addr=0x1000)[0]);assert len(binary)<=0x100
    code[:len(binary)]=binary
    image=make_pe([
        ('.text',0x1000,bytes(code),0x60000020),
        ('.rdata',RDATA,bytes(data),0x40000040),
        ('.idata',IDATA,imports,0xc0000040),
        ('.data',DATA,bytes(0x3000),0xc0000040),
        ('.reloc',RELOC,struct.pack('<IIHH',0x1000,12,0,0),0x42000040)],
        base=0x14000000,imports=(IDATA,80 if compat_rc else 60),reloc=(RELOC,12))
    # Rebuilds never overwrite a published release or Workshop upload folder.
    output=HERE/'build-output'/(version if release or compat_rc else 'experimental')
    output.mkdir(parents=True,exist_ok=True)
    manifest=dict(metadata[0],version=version,ready_status='Ready' if release or compat_rc else 'ExperimentalReady',
                  module_name=module_name,asi_sha256=hashlib.sha256(image).hexdigest(),profiles=metadata)
    manifest['routines']=dict(manifest['routines'],entry=0x1000)
    (output/module_name).write_bytes(image)
    (output/'build.asm').write_text('\n'.join(listing),encoding='utf-8')
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    (output/'README_RU.md').write_bytes((HERE/'README_RU.md').read_bytes())
    print(output/module_name,len(image),'bytes',manifest['asi_sha256'])
    return image,manifest


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    variant=parser.add_mutually_exclusive_group()
    variant.add_argument('--release',action='store_true')
    variant.add_argument('--compat-rc',action='store_true')
    variant.add_argument('--legacy-release',action='store_true',help='Reproduce 1.1.0.')
    args=parser.parse_args()
    build(release=args.release,compat_rc=args.compat_rc,legacy_release=args.legacy_release)
