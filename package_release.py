"""Build a minimal player ZIP from the verified release build. Never publishes."""
import hashlib
import json
from pathlib import Path
import zipfile

import build


def package():
    here=Path(__file__).resolve().parent
    image,manifest=build.build(release=True)
    version=manifest['version']
    assert version=='1.1.0' and manifest['ready_status']=='Ready'
    release=here/'build-output'/version
    package_dir=release/'package'
    files={
        'plugins/HT2_AutoSave.asi':image,
        'README.txt':(here/'README.txt').read_bytes(),
    }
    for name,payload in files.items():
        target=package_dir/name
        target.parent.mkdir(parents=True,exist_ok=True)
        if not target.exists() or target.read_bytes()!=payload:
            target.write_bytes(payload)
    archive=release/f'HT2_AutoSave_{version}.zip'
    if archive.exists():
        # Do not silently replace a release archive with different content.
        with zipfile.ZipFile(archive) as old:
            if set(old.namelist())!=set(files) or any(old.read(n)!=v for n,v in files.items()):
                raise RuntimeError(f'Existing archive differs; preserve it: {archive}')
    else:
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as out:
            for name,payload in files.items():
                entry=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                entry.compress_type=zipfile.ZIP_DEFLATED
                out.writestr(entry,payload)
    with zipfile.ZipFile(archive) as saved:
        assert saved.testzip() is None
        assert set(saved.namelist())==set(files)
        for name,payload in files.items():
            assert saved.read(name)==payload==(package_dir/name).read_bytes()
    hashes={name:hashlib.sha256(payload).hexdigest() for name,payload in files.items()}
    result=dict(version=version,archive=archive.name,
                archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),files=hashes,
                published=False)
    (release/'package_manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
    return result


if __name__=='__main__':package()
