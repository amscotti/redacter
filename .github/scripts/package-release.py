#!/usr/bin/env python3
"""Pack a staged release directory into tar.gz or zip."""

from __future__ import annotations

import os
import sys
import tarfile
import zipfile


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: package-release.py <tar.gz|zip> <stage-dir> <out-path>")
    archive, stage, out = sys.argv[1], sys.argv[2], sys.argv[3]
    arcname = os.path.basename(os.path.normpath(stage))
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    if archive == "zip":
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(stage):
                for name in files:
                    path = os.path.join(root, name)
                    zf.write(path, os.path.join(arcname, os.path.relpath(path, stage)))
    elif archive == "tar.gz":
        with tarfile.open(out, "w:gz") as tf:
            tf.add(stage, arcname=arcname)
    else:
        raise SystemExit(f"unknown archive {archive}")


if __name__ == "__main__":
    main()
