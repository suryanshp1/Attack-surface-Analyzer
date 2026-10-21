"""Fetch only Retire.js's offline engine and immutable advisory data, verifying pins."""
import base64
import hashlib
import io
import pathlib
import sys
import tarfile
import urllib.request

VERSION = "6.1.0"
COMMIT = "e5e228659bbcaea7ba85536a2ef8d4fb97b366e9"
INTEGRITY = "K5UdbTugJ7a793F+NA096aW0WOauZC8yRDHJZ5FthGbsyYEOQrc/oCk7+KmEQ4bnqO14dAH4S6lSM8rr66OVhA=="
FILES = {
    "repository/jsrepository.json": "01756a592875f31e99481ace7a05a9c23e6915027c719495d542709db7ee2c35",
    "LICENSE.md": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    "NOTICE.md": "5da1d2ddffe2c8286afc6d11fa6e6a0e6327ee7bc8f415771824081d81561d8e",
}


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Surfacer-build"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read((4 << 20) + 1)
    if len(data) > 4 << 20:
        raise RuntimeError("Retire.js download exceeds limit")
    return data


def main():
    output = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "output/retire")
    archive = get(f"https://registry.npmjs.org/retire/-/retire-{VERSION}.tgz")
    if base64.b64encode(hashlib.sha512(archive).digest()).decode() != INTEGRITY:
        raise RuntimeError("Retire.js release integrity mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        engine = tar.extractfile("package/lib/retire.js").read()
        license_data = tar.extractfile("package/LICENSE.md").read()
    # Download and verify everything before replacing any output files.
    files = {"retire.cjs": engine, "ENGINE-LICENSE.md": license_data}
    for name, expected in FILES.items():
        data = get(f"https://raw.githubusercontent.com/RetireJS/retire.js/{COMMIT}/{name}")
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"Retire.js snapshot checksum mismatch: {name}")
        files[pathlib.PurePosixPath(name).name] = data
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (output / name).write_bytes(data)
    print(f"Retire.js {VERSION} and advisory snapshot {COMMIT}: verified")


if __name__ == "__main__":
    main()
