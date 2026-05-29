#!/usr/bin/env python3
"""Install a Basecamp LGX module directly to the plugins directory.

Installs by extracting the package variant directly into the Basecamp plugins
directory, bypassing the in-app UI entirely.  Use this as a fallback when
the Basecamp 'Install Plugin' button is unavailable or inconvenient.

Note: Basecamp accepts unsigned LGX packages with a warning when using its
'Install Plugin' button — no signing step is required for normal distribution.

Usage:
    python3 scripts/install_lgx.py <module.lgx>

After running, restart Basecamp to load the new module.
"""
import gzip, io, json, os, pathlib, platform, sys, tarfile

def detect_variant(members):
    arch = "amd64" if platform.machine() == "x86_64" else "arm64"
    system = platform.system().lower()
    # Try variants in priority order
    for v in [f"{system}-{arch}", f"{system}-{arch}-dev", f"{system}-x86_64-dev"]:
        prefix = f"variants/{v}/"
        if any(m.name.startswith(prefix) for m in members):
            return v, prefix, f"{system}-{arch}"
    available = sorted({m.name.split("/")[1] for m in members if m.name.startswith("variants/") and "/" in m.name[9:]})
    raise SystemExit(f"No compatible variant found.\nAvailable variants: {available}")

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if sys.argv[1:] else 1)

    lgx_path = sys.argv[1]
    with gzip.open(lgx_path, "rb") as gz:
        raw = gz.read()

    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        members = tf.getmembers()
        manifest = json.loads(tf.extractfile("manifest.json").read())
        name = manifest["name"]
        variant, prefix, install_variant = detect_variant(members)

        install_dir = (
            pathlib.Path.home()
            / ".local/share/Logos/LogosBasecamp/plugins"
            / name
        )
        install_dir.mkdir(parents=True, exist_ok=True)

        for m in members:
            if not m.name.startswith(prefix) or not m.isfile():
                continue
            rel = m.name[len(prefix):]
            dest = install_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = tf.extractfile(m).read()
            dest.write_bytes(data)
            if rel.endswith(".so"):
                os.chmod(dest, 0o755)

    (install_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (install_dir / "variant").write_text(install_variant)

    print(f"Installed '{name}' to {install_dir}")
    print("Restart Basecamp to load the module.")

if __name__ == "__main__":
    main()
