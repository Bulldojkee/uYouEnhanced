#!/usr/bin/env python3
r"""Validate an IPA before extraction/injection and validate the resulting artifact.

Examples (Python 3.10+, standard library only)::

    python Scripts/ipa_preflight.py YouTube.ipa --expected-version 21.14.4
    python Scripts/ipa_preflight.py output.ipa --mode final \
        --expected-bundle-id com.google.ios.youtube --sponsorblock enabled \
        --require-dylib YouMute.dylib --require-dylib YTHoldForSpeed.dylib \
        --manifest output.ipa.json --github-output "$GITHUB_OUTPUT"

The IPA is read without extraction or modification. Validation rejects encrypted Mach-O slices,
unsafe ZIP paths and links, ambiguous app layouts and mismatched metadata.
This cannot establish that an IPA is authentic or that its patches work at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import sys
from xml.parsers.expat import ExpatError
import zipfile
import zlib


class ValidationError(ValueError):
    """The archive is not safe or does not match the requested build."""


# Resource limits cover normal YouTube IPAs while bounding untrusted archive data.
MAX_ENTRIES = 100_000
MAX_UNCOMPRESSED = 8 * 1024**3
MAX_BINARY = 512 * 1024**2
MAX_PLIST = 4 * 1024**2
THIN_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xfe\xed\xfa\xcf": (">", True),
}
FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
MACHO_MAGICS = set(THIN_MAGICS) | set(FAT_MAGICS)
LOAD_DYLIB_COMMANDS = {0xC, 0x18, 0x1F, 0x20, 0x23}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def version_tuple(value: object, label: str) -> tuple[int, ...]:
    require(isinstance(value, str) and bool(re.fullmatch(r"\d+(?:\.\d+){0,3}", value)),
            f"Invalid {label}: {value!r}")
    components = tuple(int(part) for part in value.split("."))
    return components + (0,) * (4 - len(components))


def checked_entries(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    require(0 < len(infos) <= MAX_ENTRIES, "ZIP entry count is invalid or too large")
    require(sum(info.file_size for info in infos) <= MAX_UNCOMPRESSED,
            "ZIP uncompressed size exceeds 8 GiB")
    entries: dict[str, zipfile.ZipInfo] = {}
    folded: dict[str, bool] = {}
    for info in infos:
        name = info.orig_filename
        require(name == info.filename and not any(ord(c) < 32 or ord(c) == 127 for c in name),
                "ZIP filename contains control characters")
        require(not name.startswith("/") and "\\" not in name and ":" not in name,
                f"Unsafe ZIP path: {name!r}")
        parts = name.rstrip("/").split("/")
        require(all(part not in ("", ".", "..") and not part.endswith((" ", ".")) for part in parts),
                f"Unsafe ZIP path: {name!r}")
        key = "/".join(parts).casefold()
        require(key not in folded, f"Duplicate or case-ambiguous ZIP path: {name!r}")
        kind = stat.S_IFMT(info.external_attr >> 16)
        require(kind in (0, stat.S_IFREG, stat.S_IFDIR),
                f"ZIP links and special files are forbidden: {name!r}")
        require(kind != stat.S_IFDIR or info.is_dir(), f"Inconsistent ZIP directory: {name!r}")
        require(not (info.flag_bits & 1), f"Password-encrypted ZIP entry: {name!r}")
        folded[key] = info.is_dir()
        entries[name] = info
    for key in folded:
        parts = key.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            require(parent not in folded or folded[parent], f"ZIP file shadows a directory: {parent!r}")
    return entries


def parse_thin(data: bytes | memoryview, label: str) -> dict:
    magic = bytes(data[:4])
    require(magic in THIN_MAGICS, f"{label}: invalid Mach-O slice magic")
    endian, is_64 = THIN_MAGICS[magic]
    header_size = 32 if is_64 else 28
    require(len(data) >= header_size, f"{label}: truncated Mach-O header")
    _, cpu_type, _, file_type, ncmds, sizeofcmds, _ = struct.unpack_from(endian + "7I", data)
    require(sizeofcmds <= len(data) - header_size, f"{label}: truncated Mach-O load commands")
    require(ncmds <= sizeofcmds // 8, f"{label}: impossible Mach-O load-command count")
    cursor, end = header_size, header_size + sizeofcmds
    dylibs: list[str] = []
    encryption_commands = 0
    for _ in range(ncmds):
        require(cursor + 8 <= end, f"{label}: truncated Mach-O load command")
        command, size = struct.unpack_from(endian + "2I", data, cursor)
        require(size >= 8 and size % (8 if is_64 else 4) == 0 and cursor + size <= end,
                f"{label}: invalid Mach-O load-command size")
        if command in (0x21, 0x2C):
            expected_size = 24 if command == 0x2C else 20
            require(size >= expected_size, f"{label}: truncated encryption command")
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "3I", data, cursor + 8)
            require(cryptoff + cryptsize <= len(data), f"{label}: encryption range is outside the slice")
            require(cryptid == 0, f"{label}: encrypted Mach-O slice (cryptid={cryptid}); decrypted IPA required")
            encryption_commands += 1
        if (command & 0x7FFFFFFF) in LOAD_DYLIB_COMMANDS:
            require(size >= 24, f"{label}: truncated dylib load command")
            name_offset = struct.unpack_from(endian + "I", data, cursor + 8)[0]
            require(24 <= name_offset < size, f"{label}: invalid dylib name offset")
            raw = bytes(data[cursor + name_offset:cursor + size])
            require(b"\0" in raw, f"{label}: unterminated dylib name")
            try:
                name = raw.split(b"\0", 1)[0].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValidationError(f"{label}: invalid dylib name encoding") from exc
            require(bool(name), f"{label}: empty dylib name")
            dylibs.append(name)
        cursor += size
    require(cursor == end, f"{label}: Mach-O load-command table has trailing bytes")
    return {"cpu_type": cpu_type, "file_type": file_type,
            "encryption_commands": encryption_commands, "dylibs": dylibs}


def parse_macho(data: bytes, label: str) -> list[dict]:
    magic = data[:4]
    if magic in THIN_MAGICS:
        return [parse_thin(data, label)]
    require(magic in FAT_MAGICS, f"{label}: executable is not Mach-O")
    endian, is_64 = FAT_MAGICS[magic]
    require(len(data) >= 8, f"{label}: truncated FAT header")
    count = struct.unpack_from(endian + "I", data, 4)[0]
    require(0 < count <= 64, f"{label}: invalid FAT architecture count")
    record_size = 32 if is_64 else 20
    table_end = 8 + count * record_size
    require(table_end <= len(data), f"{label}: truncated FAT architecture table")
    spans: list[tuple[int, int]] = []
    result: list[dict] = []
    for index in range(count):
        record = 8 + index * record_size
        if is_64:
            cpu_type, _, offset, size, alignment, reserved = struct.unpack_from(endian + "IIQQII", data, record)
            require(reserved == 0, f"{label}: invalid FAT64 reserved field")
        else:
            cpu_type, _, offset, size, alignment = struct.unpack_from(endian + "5I", data, record)
        require(alignment <= 63 and offset % (1 << alignment) == 0,
                f"{label}: invalid FAT slice alignment")
        require(size >= 28 and offset >= table_end and offset + size <= len(data),
                f"{label}: FAT slice is truncated or outside the file")
        require(all(offset + size <= start or offset >= stop for start, stop in spans),
                f"{label}: overlapping FAT slices")
        spans.append((offset, offset + size))
        parsed = parse_thin(memoryview(data)[offset:offset + size], f"{label} slice {index}")
        require(parsed["cpu_type"] == cpu_type, f"{label}: FAT architecture disagrees with slice")
        result.append(parsed)
    return result


def inspect_ipa(ipa: Path, *, mode: str = "input", expected_version: str = "21.14.4",
                expected_bundle_id: str | None = None, max_ios: str = "18.5",
                sponsorblock: str = "any", require_dylibs: list[str] | None = None) -> dict:
    require(mode in ("input", "final"), "Invalid validation mode")
    require(sponsorblock in ("any", "enabled", "disabled"), "Invalid SponsorBlock setting")
    require(mode != "final" or bool(expected_bundle_id), "Final validation requires --expected-bundle-id")
    version_tuple(expected_version, "expected YouTube version")
    maximum_ios = version_tuple(max_ios, "maximum iOS version")
    for name in require_dylibs or []:
        require(bool(re.fullmatch(r"[A-Za-z0-9_.+-]+\.dylib", name)),
                f"Required dylib must be a plain .dylib filename: {name!r}")
    with zipfile.ZipFile(ipa) as archive:
        entries = checked_entries(archive)
        app_plists = [name for name in entries if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
        require(len(app_plists) == 1, "IPA must contain exactly one Payload/*.app/Info.plist")
        plist_name = app_plists[0]
        app = plist_name.rsplit("/", 1)[0]
        # A second top-level .app without a plist is ambiguous too.
        app_roots = {"/".join(name.split("/")[:2]) for name in entries
                     if len(name.split("/")) >= 2 and name.startswith("Payload/")
                     and name.split("/")[1].endswith(".app")}
        require(app_roots == {app}, "IPA contains multiple top-level app bundles")
        require(entries[plist_name].file_size <= MAX_PLIST, "Main Info.plist exceeds 4 MiB")
        try:
            info = plistlib.loads(archive.read(plist_name))
        except (plistlib.InvalidFileException, ExpatError, ValueError, TypeError, OverflowError) as exc:
            raise ValidationError("Main Info.plist is invalid") from exc
        require(isinstance(info, dict), "Main Info.plist must be a dictionary")
        bundle_id = info.get("CFBundleIdentifier")
        require(isinstance(bundle_id, str) and bool(re.fullmatch(r"[A-Za-z0-9.-]+", bundle_id)),
                "Missing or invalid CFBundleIdentifier")
        if expected_bundle_id is not None:
            require(bundle_id == expected_bundle_id,
                    f"Bundle ID mismatch: expected {expected_bundle_id!r}, found {bundle_id!r}")
        version = info.get("CFBundleShortVersionString")
        version_tuple(version, "YouTube version")
        require(version == expected_version,
                f"YouTube version mismatch: expected {expected_version!r}, found {version!r}")
        minimum_ios = info.get("MinimumOSVersion")
        require(version_tuple(minimum_ios, "MinimumOSVersion") <= maximum_ios,
                f"IPA requires iOS {minimum_ios}; target device has iOS {max_ios}")
        executable = info.get("CFBundleExecutable")
        require(isinstance(executable, str) and bool(executable) and executable not in (".", "..")
                and not any(c in executable for c in ("/", "\\", ":"))
                and not any(ord(c) < 32 or ord(c) == 127 for c in executable),
                "Missing or invalid CFBundleExecutable")
        main_name = f"{app}/{executable}"
        require(main_name in entries and not entries[main_name].is_dir(), "Main executable is missing")
        binaries: dict[str, list[dict]] = {}
        for name, entry in entries.items():
            if entry.is_dir():
                continue
            with archive.open(entry) as stream:
                magic = stream.read(4)
                if magic not in MACHO_MAGICS and name != main_name:
                    continue
                require(entry.file_size <= MAX_BINARY, f"{name}: executable exceeds 512 MiB")
                data = magic + stream.read(MAX_BINARY + 1)
                require(len(data) == entry.file_size, f"{name}: unexpected executable length")
                binaries[name] = parse_macho(data, name)
        require(main_name in binaries, "Main executable is not Mach-O")
        main_slices = binaries[main_name]
        require(all(slice_["file_type"] == 2 for slice_ in main_slices),
                "Main executable contains a non-executable Mach-O slice")
        extension_ids: dict[str, str] = {}
        if mode == "final":
            extension_roots = {"/".join(parts[:index + 1]) for name in entries
                               for parts in [name.split("/")] for index, part in enumerate(parts)
                               if part.endswith(".appex")}
            for extension in sorted(extension_roots):
                relative = extension.removeprefix(app + "/PlugIns/")
                require(extension.startswith(app + "/PlugIns/") and "/" not in relative,
                        f"Extension is outside the resignable app/PlugIns directory: {extension}")
                extension_plist = extension + "/Info.plist"
                require(extension_plist in entries and entries[extension_plist].file_size <= MAX_PLIST,
                        f"Extension Info.plist is missing or too large: {extension}")
                try:
                    extension_info = plistlib.loads(archive.read(extension_plist))
                except (plistlib.InvalidFileException, ExpatError, ValueError, TypeError, OverflowError) as exc:
                    raise ValidationError(f"Invalid extension Info.plist: {extension}") from exc
                require(isinstance(extension_info, dict), f"Extension plist is not a dictionary: {extension}")
                extension_id = extension_info.get("CFBundleIdentifier")
                require(isinstance(extension_id, str) and bool(re.fullmatch(r"[A-Za-z0-9.-]+", extension_id))
                        and extension_id.startswith(bundle_id + ".") and len(extension_id) > len(bundle_id) + 1,
                        f"Extension bundle ID does not extend the main bundle ID: {extension}")
                require(extension_id not in extension_ids.values(), f"Duplicate extension bundle ID: {extension_id}")
                extension_executable = extension_info.get("CFBundleExecutable")
                require(isinstance(extension_executable, str) and bool(extension_executable)
                        and "/" not in extension_executable and "\\" not in extension_executable,
                        f"Invalid extension executable: {extension}")
                extension_binary = extension + "/" + extension_executable
                require(extension_binary in binaries
                        and all(slice_["file_type"] == 2 for slice_ in binaries[extension_binary]),
                        f"Extension executable is missing or invalid: {extension}")
                if "MinimumOSVersion" in extension_info:
                    require(version_tuple(extension_info["MinimumOSVersion"], "extension MinimumOSVersion") <= maximum_ios,
                            f"Extension requires a newer iOS version than {max_ios}: {extension}")
                extension_ids[extension] = extension_id

        def require_library(basename: str) -> None:
            matches = [name for name in entries if not entries[name].is_dir()
                       and PurePosixPath(name).name.casefold() == basename.casefold()]
            require(len(matches) == 1 and matches[0].startswith(app + "/"),
                    f"Expected exactly one {basename} inside the app")
            require(matches[0] in binaries
                    and all(slice_["file_type"] == 6 for slice_ in binaries[matches[0]]),
                    f"{basename} is not a valid Mach-O dylib")
            require(all(any(PurePosixPath(dylib).name.casefold() == basename.casefold()
                            for dylib in slice_["dylibs"]) for slice_ in main_slices),
                    f"Main executable does not load {basename} in every slice")

        for name in require_dylibs or []:
            require_library(name)
        sponsor_files = [name for name in entries if not entries[name].is_dir()
                         and PurePosixPath(name).name.casefold() == "isponsorblock.dylib"]
        loaded = [any(PurePosixPath(dylib).name.casefold() == "isponsorblock.dylib"
                      for dylib in slice_["dylibs"]) for slice_ in main_slices]
        if sponsorblock == "enabled":
            require_library("iSponsorBlock.dylib")
        if sponsorblock == "disabled":
            any_reference = any(PurePosixPath(dylib).name.casefold() == "isponsorblock.dylib"
                                for slices in binaries.values() for slice_ in slices
                                for dylib in slice_["dylibs"])
            require(not sponsor_files and not any_reference,
                    "SponsorBlock is disabled but its dylib or a load reference remains")
    sha256 = hashlib.sha256()
    with ipa.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024**2), b""):
            sha256.update(chunk)
    return {"schema_version": 1, "mode": mode, "ipa_filename": ipa.name,
            "sha256": sha256.hexdigest(), "size_bytes": ipa.stat().st_size,
            "bundle_id": bundle_id, "youtube_version": version,
            "minimum_ios": minimum_ios, "target_ios": max_ios, "app_path": app,
            "macho_file_count": len(binaries), "main_architecture_count": len(main_slices),
            "sponsorblock_present": bool(sponsor_files), "sponsorblock_loaded": all(loaded),
            "required_dylibs": require_dylibs or [], "extension_bundle_ids": extension_ids}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--mode", choices=("input", "final"), default="input")
    parser.add_argument("--expected-version", default="21.14.4")
    parser.add_argument("--expected-bundle-id")
    parser.add_argument("--max-ios", default="18.5")
    parser.add_argument("--sponsorblock", choices=("any", "enabled", "disabled"), default="any")
    parser.add_argument("--require-dylib", action="append", default=[],
                        help="Require this injected dylib and a main-executable load command; repeatable")
    parser.add_argument("--manifest", type=Path, help="Write validated artifact metadata and SHA-256 as JSON")
    parser.add_argument("--github-output", type=Path, help="Append metadata to the supplied GitHub Actions output file")
    args = parser.parse_args(argv)
    try:
        result = inspect_ipa(args.ipa, mode=args.mode, expected_version=args.expected_version,
                             expected_bundle_id=args.expected_bundle_id, max_ios=args.max_ios,
                             sponsorblock=args.sponsorblock, require_dylibs=args.require_dylib)
        serialized = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
        if args.manifest:
            require(args.manifest.resolve() != args.ipa.resolve(), "Manifest cannot overwrite the input IPA")
            args.manifest.write_text(serialized, encoding="utf-8")
        if args.github_output:
            require(args.github_output.resolve() != args.ipa.resolve(), "GitHub outputs cannot overwrite the input IPA")
            require(not args.manifest or args.github_output.resolve() != args.manifest.resolve(),
                    "Manifest and GitHub output must be different files")
            with args.github_output.open("a", encoding="utf-8") as stream:
                for key in ("bundle_id", "youtube_version", "sha256", "minimum_ios", "app_path"):
                    stream.write(f"{key}={result[key]}\n")
        print(serialized, end="")
        return 0
    except (ValidationError, OSError, zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError) as exc:
        print(f"IPA validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
