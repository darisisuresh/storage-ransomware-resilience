#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys

ROOT=Path(__file__).resolve().parents[1]
DENIED_EXT={'.docx','.doc','.pdf','.tex'}
DENIED_PARTS={'raw','private','extracted-text','reports'}
DENIED_TEXT=('co-authored-'+'by:','open'+'ai','co'+'dex','/users/'+'eb1a','/users/'+'suresh','@rocket'+'software.com')

def tracked():
    p=subprocess.run(['git','ls-files'],cwd=ROOT,text=True,capture_output=True)
    return [ROOT/x for x in p.stdout.splitlines()] if p.returncode==0 else [x for x in ROOT.rglob('*') if x.is_file() and '.git' not in x.parts]

def scan(paths):
    errors=[]
    for p in paths:
        try: rel=p.relative_to(ROOT)
        except ValueError: rel=Path(p.name)
        if p.suffix.lower() in DENIED_EXT or any(x.lower() in DENIED_PARTS for x in rel.parts): errors.append(f'forbidden path: {rel}'); continue
        try: data=p.read_text(errors='ignore').lower()
        except OSError: continue
        for needle in DENIED_TEXT:
            if needle in data: errors.append(f'forbidden text {needle!r}: {rel}')
    return errors

if __name__=='__main__':
    errors=scan(tracked())
    if errors:
        print('\n'.join(errors)); sys.exit(1)
    print('privacy check passed')
