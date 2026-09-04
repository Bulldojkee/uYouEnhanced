#!/usr/bin/env python3
"""Copy a YouTube IPA without ExtensionKit bundles that cannot be resigned.

This does not decrypt anything. The original remains unchanged. All remaining
code is checked by ipa_preflight before the build input is accepted.
"""

import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

from ipa_preflight import ValidationError, checked_entries, inspect_ipa, require


def prepare(source, destination, expected_version="21.14.4", max_ios="18.5"):
    source, destination = Path(source), Path(destination)
    require(source.resolve() != destination.resolve(), "Source IPA must remain unchanged")
    require(not destination.exists(), "Output already exists; choose a new build-input path")
    removed = []
    with tempfile.TemporaryDirectory(prefix="ipa-prepare-", dir=destination.parent) as temp:
        pending = Path(temp) / "input.ipa"
        with zipfile.ZipFile(source) as original:
            entries = checked_entries(original)
            app_plists = [n for n in entries if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
            require(len(app_plists) == 1, "Expected exactly one application Info.plist")
            app = app_plists[0].rsplit("/", 1)[0]
            excluded = app + "/Extensions/"
            with zipfile.ZipFile(pending, "w") as output:
                for name, entry in entries.items():
                    if name.startswith(excluded):
                        removed.append(name)
                        continue
                    with original.open(entry) as reader, output.open(entry, "w") as writer:
                        shutil.copyfileobj(reader, writer, 1024 * 1024)
        manifest = inspect_ipa(pending, expected_version=expected_version, max_ios=max_ios)
        pending.replace(destination)
    manifest["ipa_filename"] = destination.name
    manifest["removed_extensionkit_entries"] = len(removed)
    manifest["removed_extensionkit_bundles"] = sorted({
        n.split(".appex/", 1)[0] + ".appex" for n in removed if ".appex/" in n
    })
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--expected-version", default="21.14.4")
    parser.add_argument("--max-ios", default="18.5")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    if args.manifest:
        require(args.manifest.resolve() not in (args.source.resolve(), args.destination.resolve()),
                "Manifest must not overwrite an IPA")
    result = prepare(args.source, args.destination, args.expected_version, args.max_ios)
    text = json.dumps(result, indent=2) + "\n"
    if args.manifest:
        args.manifest.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
