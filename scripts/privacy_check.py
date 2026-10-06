#!/usr/bin/env python3
from pathlib import Path
import re, subprocess, sys

ROOT=Path(__file__).resolve().parents[1]
DENIED_EXT={'.docx','.doc','.pdf','.tex'}
DENIED_PARTS={'raw','private','extracted-text','reports'}
DENIED_TEXT=('co-authored-'+'by:','open'+'ai','co'+'dex','/users/'+'eb1a','/users/'+'suresh','@rocket'+'software.com')
SECRET_PATTERNS=(
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', re.I),
    re.compile(r'gh[pousr]_[A-Za-z0-9_]{30,}'),
)

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
        for pattern in SECRET_PATTERNS:
            if pattern.search(data): errors.append(f'possible secret {pattern.pattern!r}: {rel}')
    return errors

def scan_history():
    errors=[]
    names=subprocess.run(['git','log','--all','--name-only','--pretty=format:'],cwd=ROOT,text=True,capture_output=True,check=True).stdout.splitlines()
    for name in sorted(set(filter(None,names))):
        path=Path(name)
        if path.suffix.lower() in DENIED_EXT or any(x.lower() in DENIED_PARTS for x in path.parts):
            errors.append(f'forbidden historical path: {name}')
    patches=subprocess.run(['git','log','--all','-p','--format='],cwd=ROOT,text=True,capture_output=True,errors='ignore',check=True).stdout.lower()
    for needle in DENIED_TEXT:
        if needle in patches: errors.append(f'forbidden text in git history: {needle!r}')
    for pattern in SECRET_PATTERNS:
        if pattern.search(patches): errors.append(f'possible secret in git history: {pattern.pattern!r}')
    return errors

if __name__=='__main__':
    errors=scan(tracked())
    if '--history' in sys.argv:
        errors.extend(scan_history())
    if errors:
        print('\n'.join(errors)); sys.exit(1)
    print('privacy check passed')
