"""Download pinned official release binaries and verify their published SHA-256 checksums."""
import hashlib, io, json, os, pathlib, sys, urllib.request, zipfile, tarfile
VERSIONS = {'subfinder':'2.17.0','dnsx':'1.3.1','httpx':'1.12.0','nuclei':'3.11.1','katana':'1.8.0','gitleaks':'8.30.1','naabu':'2.6.1','tlsx':'1.4.0','gau':'2.2.4'}
arch=sys.argv[1] if len(sys.argv)>1 else 'arm64'
out=pathlib.Path(sys.argv[2] if len(sys.argv)>2 else 'output/scanners');out.mkdir(parents=True,exist_ok=True)
for tool,version in VERSIONS.items():
    repo = {'gitleaks':'gitleaks/gitleaks','gau':'lc/gau'}.get(tool,f'projectdiscovery/{tool}')
    release_arch = ('x64' if arch == 'amd64' else arch) if tool == 'gitleaks' else arch
    name=f'{tool}_{version}_linux_{release_arch}.' + ('tar.gz' if tool in ['gitleaks','gau'] else 'zip')
    base=f'https://github.com/{repo}/releases/download/v{version}/' 
    def get(url):return urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Surfacer-build'}),timeout=120).read()
    checksum_name = f'katana-{version}-checksums.txt' if tool == 'katana' else ('naabu-checksums.txt' if tool=='naabu' else f'{tool}_{version}_checksums.txt')
    checks=get(base+checksum_name).decode()
    expected=next(line.split()[0] for line in checks.splitlines() if line.split()[-1].lstrip('*')==name)
    archive=get(base+name)
    if hashlib.sha256(archive).hexdigest()!=expected:raise RuntimeError(f'Checksum mismatch: {tool}')
    if tool in ['gitleaks','gau']:
        tar=tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz')
        content={m.name:tar.extractfile(m).read() for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name in [tool,'LICENSE']}
        class Archive:
            def read(self,name):return content[name]
            def namelist(self):return list(content)
        z=Archive()
    else:
        z=zipfile.ZipFile(io.BytesIO(archive))
    binary=z.read(tool);path=out/tool;path.write_bytes(binary);path.chmod(0o755)
    license_names=[name for name in z.namelist() if pathlib.PurePosixPath(name).name.lower().startswith('license')]
    if license_names:
        license_data=z.read(license_names[0])
    else:
        license_data=None
        for license_name in ['LICENSE.md','LICENSE']:
            try:
                license_data=get(f'https://raw.githubusercontent.com/{repo}/v{version}/{license_name}');break
            except urllib.error.HTTPError as error:
                if error.code!=404:raise
        if license_data is None:raise RuntimeError(f'License missing: {tool}')
    (out/f'{tool}.LICENSE').write_bytes(license_data)
    print(f'{tool} v{version}: verified',flush=True)
(out/'versions.json').write_text(json.dumps(VERSIONS))
