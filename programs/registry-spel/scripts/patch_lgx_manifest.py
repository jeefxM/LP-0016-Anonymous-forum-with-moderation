#!/usr/bin/env python3
"""Replace manifest.json in an LGX archive with a pre-generated manifest file.
Usage: python3 scripts/patch_lgx_manifest.py <pkg.lgx> <manifest.json>
"""
import sys, tarfile, gzip, json, io

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pkg.lgx> <manifest.json>", file=sys.stderr)
        sys.exit(1)
    lgx_path, manifest_path = sys.argv[1], sys.argv[2]
    manifest = json.load(open(manifest_path))

    with gzip.open(lgx_path, "rb") as gz:
        raw = gz.read()
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        members = [
            (m, tf.extractfile(m).read() if m.isfile() else None)
            for m in tf.getmembers()
        ]

    # Keep only manifest "main" entries whose variant directory actually exists in the archive.
    archive_variants = {
        m.name.split("/")[1]
        for m, _ in members
        if m.name.startswith("variants/") and m.name.count("/") >= 1 and m.name.split("/")[1]
    }
    if "main" in manifest and archive_variants:
        manifest["main"] = {k: v for k, v in manifest["main"].items() if k in archive_variants}

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz_out:
        with tarfile.open(fileobj=gz_out, mode="w") as tf_out:
            mb = json.dumps(manifest, indent=2, sort_keys=True).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(mb)
            info.mtime = info.uid = info.gid = 0
            info.mode = 0o644
            tf_out.addfile(info, io.BytesIO(mb))
            for m, data in members:
                if m.name == "manifest.json":
                    continue
                tf_out.addfile(m, io.BytesIO(data)) if data is not None else tf_out.addfile(m)

    with open(lgx_path, "wb") as f:
        f.write(buf.getvalue())
    print(f"Patched {lgx_path}: manifest.json replaced from {manifest_path}")

if __name__ == "__main__":
    main()
