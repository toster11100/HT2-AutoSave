"""Fixed offline-verified address maps. No runtime signature scanning/guessing."""
import hashlib
import json
import os
from pathlib import Path

HERE=Path(__file__).resolve().parent
PROFILES=json.loads((HERE/'exe_profiles.json').read_text(encoding='utf-8'))
PROFILE_ALIASES={
    'SO':'KOTR81','SteamOriginal':'KOTR81','SteamRU':'KOTR81','KOTR81':'KOTR81',
    'FR':'KOTR13','SteamFrench':'KOTR13','SteamWW':'KOTR13','KOTR13':'KOTR13',
    'MC':'ModifiedCore82','ModifiedCore82':'ModifiedCore82',
}


def canonical_profile(key):
    return PROFILE_ALIASES.get(key,key)


def profile_key(key):
    return {'KOTR81':'SO','KOTR13':'FR','ModifiedCore82':'MC'}.get(
        canonical_profile(key),key)


def input_file(name):
    root=os.environ.get('HT2_BUILD_INPUTS')
    if not root:
        raise RuntimeError('Set HT2_BUILD_INPUTS to the private game-reference directory.')
    if Path(name).name!=name:
        raise ValueError('Build input must be a filename.')
    path=(Path(root)/name).resolve()
    try:
        path.relative_to(HERE.resolve())
    except ValueError:
        return path
    raise ValueError('Private build inputs must be outside the repository.')


def address(key,va):
    key=profile_key(key)
    if va in {int.from_bytes(s.encode(),'little') for s in ['eng','rus','fre','fra','ger','deu','spa','esp']}:
        return va  # language prefixes, not pointers
    if key=='SO' or va in (0x400000,0x40003c) or not 0x400000<=va<0x800000:return va
    p=PROFILES[key]
    if str(va) in p['addresses']:return p['addresses'][str(va)]
    values={dst+va-src for src,dst,n in p['ranges'] if src<=va<src+n}
    if len(values)!=1:raise ValueError(f'Unverified address {key}: {va:08X}')
    return values.pop()


def reference(key):
    key=profile_key(key)
    p=PROFILES[key]
    path=input_file(p['file'])
    if hashlib.sha256(path.read_bytes()).hexdigest()!=p['sha256']:
        raise ValueError(f'Reference SHA mismatch: {key}')
    return path
