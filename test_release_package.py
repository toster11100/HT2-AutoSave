"""Verify the player ZIP contains only the AutoSave plugin and instructions."""
from pathlib import Path
import tempfile
import unittest
import zipfile

import package_release
from test_ini_win32 import WindowsIniMachine

HERE=Path(__file__).resolve().parent


class PackageTests(unittest.TestCase):
    def test_release_archive_has_an_explicit_safe_file_list(self):
        result=package_release.package()
        self.assertEqual(result['version'],'1.1.0')
        self.assertEqual(set(result['files']),{
            'plugins/HT2_AutoSave.asi','README.txt'})
        archive=HERE/'build-output/1.1.0'/result['archive']
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(bundle.testzip(),None)
            self.assertEqual(set(bundle.namelist()),set(result['files']))
            for name in bundle.namelist():
                self.assertFalse(name.lower().endswith(('.exe','.dll','.ini','.pl1')))

    def test_package_file_list_preserves_runtime_generated_ini(self):
        package_release.package()
        staged=HERE/'build-output/1.1.0/package'
        with tempfile.TemporaryDirectory(prefix='HT2_AutoSave_Update_') as directory:
            target=Path(directory);(target/'plugins').mkdir()
            ini=target/'plugins/HT2_AutoSave.ini'
            first=WindowsIniMachine(ini);first.install()
            custom=b'; user-owned configuration\r\n[AutoSave]\r\nIntervalMinutes=19\r\n'
            ini.write_bytes(custom)
            managed=[]
            for source in staged.rglob('*'):
                if source.is_file():
                    relative=source.relative_to(staged);managed.append(str(relative))
                    dest=target/relative;dest.parent.mkdir(parents=True,exist_ok=True)
                    dest.write_bytes(source.read_bytes())
            self.assertNotIn('plugins\\HT2_AutoSave.ini',managed)
            self.assertEqual(ini.read_bytes(),custom)
            updated=WindowsIniMachine(ini);updated.install()
            self.assertEqual(updated.get('IntervalMinutes'),1140000)
            self.assertEqual(ini.read_bytes(),custom)


if __name__=='__main__':unittest.main(verbosity=2)
