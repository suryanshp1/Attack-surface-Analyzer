"""Create a private Postgres snapshot. Evidence objects need a separate S3 backup.
Usage: python3 scripts/backup.py /absolute/path/to/new-backup.dump
Never overwrites an existing backup; no credentials are printed or copied.
"""
import hashlib, os, pathlib, subprocess, sys
if len(sys.argv) != 2:
    raise SystemExit(__doc__)
path = pathlib.Path(sys.argv[1]).resolve()
path.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(fd, 'wb') as output:
        subprocess.run(['docker','compose','exec','-T','db','pg_dump','-U','surfacer','-d','surfacer','--format=custom','--no-owner','--no-acl'], stdout=output, check=True)
    # Verify the archive index can be read without restoring over live data.
    with path.open('rb') as source:
        subprocess.run(['docker','compose','exec','-T','db','pg_restore','--list'], stdin=source, stdout=subprocess.DEVNULL, check=True)
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    checksum = pathlib.Path(str(path)+'.sha256')
    with os.fdopen(os.open(checksum, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),'w') as output:
        output.write(digest+'  '+path.name+'\n')
    print('Database snapshot created; archive index verified. Back up the evidence bucket separately.')
except Exception:
    path.unlink(missing_ok=True)
    raise
