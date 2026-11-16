"""Run the same emitted-machine-code regression suite on each real EXE.

Only address literals change, through the fixed reviewed map. Expectations,
heap layouts, operation ordering and stack offsets remain identical.
"""
import ast
from pathlib import Path
import types
import unittest

import profiles
RELEASE_REQUESTED='--release' in __import__('sys').argv


def suite_for(key):
    if RELEASE_REQUESTED and '--release' not in __import__('sys').argv:
        __import__('sys').argv.append('--release')
    path=Path(__file__).with_name('test_mod.py')
    tree=ast.parse(path.read_text(encoding='utf-8'),str(path))
    class Addresses(ast.NodeTransformer):
        def visit_Constant(self,node):
            if isinstance(node.value,int) and not isinstance(node.value,bool):
                value=profiles.address(key,node.value)
                if value!=node.value:return ast.copy_location(ast.Constant(value=value),node)
            return node
    tree=ast.fix_missing_locations(Addresses().visit(tree))
    module=types.ModuleType('autosave_tests_'+key)
    module.__file__=str(path)
    exec(compile(tree,str(path),'exec'),module.__dict__)
    original=module.b
    facade=types.SimpleNamespace(**vars(original))
    profile=next(p for p in module.MANIFEST['profiles']
                 if p['key']==profiles.profile_key(key))
    facade.EXE=profiles.reference(key)
    facade.R=dict(profile['routines'],entry=0x1000)
    facade.HOOKS=[(name,profiles.address(key,va),n) for name,va,n in original.HOOKS]
    facade.GUARDS=[(profiles.address(key,va),n) for va,n in original.GUARDS]
    module.b=facade
    module.PROFILE_NAME=profile['name']
    return module.AutoSaveTests


class ProfileAliasTests(unittest.TestCase):
    def test_legacy_identifiers_resolve_to_neutral_profiles(self):
        self.assertEqual(profiles.canonical_profile('SteamRU'),'KOTR81')
        self.assertEqual(profiles.canonical_profile('SteamWW'),'KOTR13')
        self.assertEqual(profiles.canonical_profile('SteamFrench'),'KOTR13')
        self.assertEqual(profiles.canonical_profile('MC'),'ModifiedCore82')
        self.assertEqual(profiles.profile_key('KOTR81'),'SO')
        self.assertEqual(profiles.profile_key('KOTR13'),'FR')
        self.assertEqual(profiles.address('SteamWW',0x127134),
                         profiles.address('KOTR13',0x127134))


KOTR13Tests=suite_for('KOTR13')
Core82Tests=suite_for('ModifiedCore82')


if __name__=='__main__':unittest.main(verbosity=2)
