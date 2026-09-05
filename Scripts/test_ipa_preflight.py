"""Synthetic IPA regression tests; no Apple binaries or network access needed."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import plistlib
import stat
import struct
import tempfile
import unittest
import zipfile

import ipa_preflight as check


def thin(*, encrypted=0, encryption=True, dylib=None, file_type=2, endian="<", is_64=True):
    commands = []
    if encryption:
        command = struct.pack(endian + ("6I" if is_64 else "5I"),
                              *([0x2C, 24, 0, 0, encrypted, 0] if is_64 else [0x21, 20, 0, 0, encrypted]))
        commands.append(command)
    if dylib:
        raw = dylib.encode() + b"\0"
        alignment = 8 if is_64 else 4
        size = ((24 + len(raw) + alignment - 1) // alignment) * alignment
        commands.append(struct.pack(endian + "6I", 0xC, size, 24, 0, 0, 0) + raw + bytes(size - 24 - len(raw)))
    cpu = 0x100000C if is_64 else 12
    header = struct.pack(endian + "7I", 0xFEEDFACF if is_64 else 0xFEEDFACE,
                         cpu, 0, file_type, len(commands), sum(map(len, commands)), 0)
    return header + (bytes(4) if is_64 else b"") + b"".join(commands)


def fat(slices, *, is_64=False, endian=">"):
    record_size = 32 if is_64 else 20
    offset = 8 + record_size * len(slices)
    records = []
    for item in slices:
        cpu = check.parse_thin(item, "fixture")["cpu_type"]
        values = [cpu, 0, offset, len(item), 0] + ([0] if is_64 else [])
        records.append(struct.pack(endian + ("IIQQII" if is_64 else "5I"), *values))
        offset += len(item)
    return struct.pack(endian + "2I", 0xCAFEBABF if is_64 else 0xCAFEBABE, len(slices)) + b"".join(records + slices)


class IPATests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.ipa"

    def make_ipa(self, *, executable=None, info_updates=None, extras=()):
        info = {"CFBundleIdentifier": "com.google.ios.youtube", "CFBundleExecutable": "YouTube",
                "CFBundleShortVersionString": "21.14.4", "MinimumOSVersion": "16.0"}
        info.update(info_updates or {})
        with zipfile.ZipFile(self.path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Payload/YouTube.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
            archive.writestr("Payload/YouTube.app/YouTube", thin() if executable is None else executable)
            for name, data in extras:
                archive.writestr(name, data)
        return self.path

    def rejects(self, pattern, **kwargs):
        with self.assertRaisesRegex(check.ValidationError, pattern):
            check.inspect_ipa(self.path, **kwargs)

    def test_valid_input_and_sha256(self):
        self.make_ipa(extras=[("Payload/YouTube.app/Frameworks/helper.dylib", thin(file_type=6, encryption=False))])
        result = check.inspect_ipa(self.path)
        self.assertEqual(result["bundle_id"], "com.google.ios.youtube")
        self.assertEqual(result["macho_file_count"], 2)
        self.assertEqual(result["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_matching_final_bundle_id_and_enabled_sponsorblock(self):
        self.make_ipa(executable=thin(dylib="@executable_path/Frameworks/iSponsorBlock.dylib"), extras=[
            ("Payload/YouTube.app/Frameworks/iSponsorBlock.dylib", thin(file_type=6, encryption=False))])
        result = check.inspect_ipa(self.path, mode="final", expected_bundle_id="com.google.ios.youtube", sponsorblock="enabled")
        self.assertTrue(result["sponsorblock_loaded"])

    def test_final_requires_bundle_id(self):
        self.make_ipa()
        self.rejects("requires --expected-bundle-id", mode="final")

    def test_bundle_id_mismatch(self):
        self.make_ipa()
        self.rejects("Bundle ID mismatch", mode="final", expected_bundle_id="com.other.youtube")

    def test_version_mismatch(self):
        self.make_ipa(info_updates={"CFBundleShortVersionString": "19.21.2"})
        self.rejects("YouTube version mismatch")
        self.assertEqual(check.inspect_ipa(self.path, expected_version="19.21.2")["youtube_version"], "19.21.2")

    def test_ios_compatibility(self):
        self.make_ipa(info_updates={"MinimumOSVersion": "18.5.1"})
        self.rejects("requires iOS 18.5.1")
        self.make_ipa(info_updates={"MinimumOSVersion": "18.5.0"})
        self.assertEqual(check.inspect_ipa(self.path)["minimum_ios"], "18.5.0")

    def test_invalid_minimum_ios(self):
        self.make_ipa(info_updates={"MinimumOSVersion": "18.x"})
        self.rejects("Invalid MinimumOSVersion")

    def test_encrypted_main_and_embedded_code(self):
        for executable, extras in ((thin(encrypted=1), []), (thin(), [
                ("Payload/YouTube.app/Frameworks/Helper.framework/Helper", thin(encrypted=1, file_type=6))])):
            with self.subTest(extras=bool(extras)):
                self.make_ipa(executable=executable, extras=extras)
                self.rejects("cryptid=1")

    def test_macho_all_word_sizes_and_endianness(self):
        for endian in ("<", ">"):
            for is_64 in (False, True):
                with self.subTest(endian=endian, is_64=is_64):
                    self.make_ipa(executable=thin(endian=endian, is_64=is_64))
                    self.assertEqual(check.inspect_ipa(self.path)["main_architecture_count"], 1)

    def test_fat_all_word_sizes_and_endianness(self):
        for endian in ("<", ">"):
            for is_64 in (False, True):
                with self.subTest(endian=endian, is_64=is_64):
                    self.make_ipa(executable=fat([thin(), thin(is_64=False)], endian=endian, is_64=is_64))
                    self.assertEqual(check.inspect_ipa(self.path)["main_architecture_count"], 2)

    def test_encrypted_second_fat_slice(self):
        data = bytearray(fat([thin(), thin()]))
        second_offset = struct.unpack_from(">I", data, 8 + 20 + 8)[0]
        struct.pack_into("<I", data, second_offset + 32 + 16, 1)
        self.make_ipa(executable=bytes(data))
        self.rejects("slice 1: encrypted")

    def test_fat_overlapping_and_truncated_slices(self):
        data = bytearray(fat([thin(), thin()]))
        first_offset = struct.unpack_from(">I", data, 16)[0]
        struct.pack_into(">I", data, 36, first_offset)
        self.make_ipa(executable=bytes(data))
        self.rejects("overlapping FAT")
        self.make_ipa(executable=fat([thin()])[:-1])
        self.rejects("truncated or outside")

    def test_malformed_load_command(self):
        data = bytearray(thin())
        struct.pack_into("<I", data, 36, 0)
        self.make_ipa(executable=bytes(data))
        self.rejects("load-command size")

    def test_truncated_encryption_command(self):
        data = bytearray(thin())
        struct.pack_into("<I", data, 20, 8)
        struct.pack_into("<I", data, 36, 8)
        self.make_ipa(executable=bytes(data[:40]))
        self.rejects("truncated encryption")

    def test_main_must_be_executable_macho(self):
        self.make_ipa(executable=b"not executable")
        self.rejects("not Mach-O")
        self.make_ipa(executable=thin(file_type=6))
        self.rejects("non-executable")

    def test_truncated_macho_header(self):
        self.make_ipa(executable=thin()[:12])
        self.rejects("truncated Mach-O header")

    def test_invalid_main_plist(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("Payload/YouTube.app/Info.plist", b'<?xml version="1.0"?><plist><dict>')
            archive.writestr("Payload/YouTube.app/YouTube", thin())
        self.rejects("Main Info.plist is invalid")

    def test_unsafe_zip_paths(self):
        for name in ("../escape", "/absolute", "Payload/../escape", "Payload\\escape", "C:/escape", "Payload//double", "Payload/trailing.", "Payload/line\nbreak"):
            with self.subTest(name=name):
                item = zipfile.ZipInfo("placeholder")
                # Force the raw archive name; ZipInfo otherwise normalizes backslashes on Windows.
                item.filename = name
                self.make_ipa(extras=[(item, b"x")])
                self.rejects("Unsafe ZIP|control characters")

    def test_symlink_rejected(self):
        item = zipfile.ZipInfo("Payload/YouTube.app/link")
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.make_ipa(extras=[(item, b"../../escape")])
        self.rejects("links and special files")

    def test_case_ambiguous_entries_and_parent_file(self):
        self.make_ipa(extras=[("Payload/YouTube.app/info.plist", b"duplicate")])
        self.rejects("case-ambiguous")
        self.make_ipa(extras=[("Payload/YouTube.app/Frameworks", b"file"), ("Payload/YouTube.app/Frameworks/x", b"x")])
        self.rejects("shadows a directory")

    def test_multiple_or_missing_main_plists(self):
        self.make_ipa(extras=[("Payload/Other.app/Info.plist", b"x")])
        self.rejects("exactly one")
        self.make_ipa(extras=[("Payload/Other.app/file", b"x")])
        self.rejects("multiple top-level")
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("Payload/YouTube.app/nothing", b"x")
        self.rejects("exactly one")

    def test_sponsorblock_requires_library_and_load_command(self):
        self.make_ipa(executable=thin(dylib="@rpath/iSponsorBlock.dylib"))
        self.rejects("exactly one iSponsorBlock", sponsorblock="enabled")
        self.make_ipa(extras=[("Payload/YouTube.app/iSponsorBlock.dylib", thin(file_type=6, encryption=False))])
        self.rejects("does not load", sponsorblock="enabled")
        self.make_ipa(executable=thin(dylib="@rpath/iSponsorBlock.dylib"), extras=[("Payload/YouTube.app/iSponsorBlock.dylib", b"fake")])
        self.rejects("not a valid Mach-O dylib", sponsorblock="enabled")

    def test_sponsorblock_all_fat_slices_must_load(self):
        self.make_ipa(executable=fat([thin(dylib="@rpath/iSponsorBlock.dylib"), thin()]), extras=[
            ("Payload/YouTube.app/iSponsorBlock.dylib", thin(file_type=6, encryption=False))])
        self.rejects("every slice", sponsorblock="enabled")

    def test_disabled_sponsorblock_rejects_residual_files_and_indirect_loads(self):
        for extra in (("Payload/YouTube.app/iSponsorBlock.dylib", thin(file_type=6)),
                      ("Payload/YouTube.app/helper.dylib", thin(file_type=6, dylib="@rpath/iSponsorBlock.dylib"))):
            with self.subTest(extra=extra[0]):
                self.make_ipa(extras=[extra])
                self.rejects("disabled but", sponsorblock="disabled")
        self.make_ipa()
        self.assertFalse(check.inspect_ipa(self.path, sponsorblock="disabled")["sponsorblock_present"])

    def test_cli_manifest_and_github_output(self):
        self.make_ipa()
        manifest = Path(self.temp.name) / "artifact.json"
        outputs = Path(self.temp.name) / "github-output"
        with contextlib.redirect_stdout(io.StringIO()):
            code = check.main([str(self.path), "--mode", "final", "--expected-bundle-id", "com.google.ios.youtube",
                               "--manifest", str(manifest), "--github-output", str(outputs)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(manifest.read_text())["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertIn("bundle_id=com.google.ios.youtube\n", outputs.read_text())

    def test_cli_failure_emits_no_manifest(self):
        self.make_ipa(executable=thin(encrypted=1))
        manifest = Path(self.temp.name) / "artifact.json"
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(check.main([str(self.path), "--manifest", str(manifest)]), 1)
        self.assertFalse(manifest.exists())

    def test_cli_cannot_overwrite_ipa(self):
        self.make_ipa()
        original = self.path.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(check.main([str(self.path), "--manifest", str(self.path)]), 1)
        self.assertEqual(self.path.read_bytes(), original)

    def extension(self, root="Payload/YouTube.app/PlugIns/Widget.appex", bundle_id="com.google.ios.youtube.Widget"):
        info = {"CFBundleIdentifier": bundle_id, "CFBundleExecutable": "Widget", "MinimumOSVersion": "16.0"}
        return [(root + "/Info.plist", plistlib.dumps(info)), (root + "/Widget", thin())]

    def test_final_extension_bundle_ids(self):
        self.make_ipa(extras=self.extension())
        result = check.inspect_ipa(self.path, mode="final", expected_bundle_id="com.google.ios.youtube")
        self.assertEqual(list(result["extension_bundle_ids"].values()), ["com.google.ios.youtube.Widget"])
        self.make_ipa(extras=self.extension(bundle_id="com.other.Widget"))
        self.rejects("does not extend", mode="final", expected_bundle_id="com.google.ios.youtube")

    def test_final_extension_must_be_resignable(self):
        self.make_ipa(extras=self.extension(root="Payload/YouTube.app/Extensions/Widget.appex"))
        self.rejects("outside the resignable", mode="final", expected_bundle_id="com.google.ios.youtube")
        self.make_ipa(extras=self.extension()[:1])
        self.rejects("executable is missing", mode="final", expected_bundle_id="com.google.ios.youtube")

    def test_required_dylib_present_and_loaded(self):
        self.make_ipa(executable=thin(dylib="@executable_path/Frameworks/YouMute.dylib"), extras=[
            ("Payload/YouTube.app/Frameworks/YouMute.dylib", thin(file_type=6, encryption=False))])
        self.assertEqual(check.inspect_ipa(self.path, require_dylibs=["YouMute.dylib"])["required_dylibs"], ["YouMute.dylib"])
        self.rejects("exactly one YTHoldForSpeed", require_dylibs=["YouMute.dylib", "YTHoldForSpeed.dylib"])
        self.make_ipa(extras=[("Payload/YouTube.app/Frameworks/YouMute.dylib", thin(file_type=6))])
        self.rejects("does not load YouMute", require_dylibs=["YouMute.dylib"])


if __name__ == "__main__":
    unittest.main()
