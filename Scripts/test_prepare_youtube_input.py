import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

from ipa_preflight import ValidationError
from prepare_youtube_input import prepare
import test_ipa_preflight as fixtures
from test_ipa_preflight import thin


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.IPATests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.output = self.fixture.path.parent / "prepared.ipa"

    def test_remove_encrypted_extension_without_changing_source(self):
        source = self.fixture.make_ipa(extras=[
            ("Payload/YouTube.app/Extensions/AppMigrationExtension.appex/Binary", thin(encrypted=1)),
            ("Payload/YouTube.app/PlugIns/Share.appex/Binary", thin()),
        ])
        before = hashlib.sha256(source.read_bytes()).digest()
        result = prepare(source, self.output)
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), before)
        self.assertEqual(result["removed_extensionkit_entries"], 1)
        with zipfile.ZipFile(self.output) as z:
            self.assertIn("Payload/YouTube.app/PlugIns/Share.appex/Binary", z.namelist())
            self.assertFalse(any("/Extensions/" in n for n in z.namelist()))

    def test_encrypted_main_is_still_rejected(self):
        source = self.fixture.make_ipa(executable=thin(encrypted=1))
        with self.assertRaisesRegex(ValidationError, "encrypted Mach-O"):
            prepare(source, self.output)
        self.assertFalse(self.output.exists())

    def test_encrypted_framework_is_still_rejected(self):
        source = self.fixture.make_ipa(extras=[
            ("Payload/YouTube.app/Frameworks/Bad.dylib", thin(encrypted=1, file_type=6))])
        with self.assertRaisesRegex(ValidationError, "encrypted Mach-O"):
            prepare(source, self.output)
        self.assertFalse(self.output.exists())

    def test_cannot_overwrite_original_or_existing_output(self):
        source = self.fixture.make_ipa()
        with self.assertRaisesRegex(ValidationError, "unchanged"):
            prepare(source, source)
        self.output.write_bytes(b"keep")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            prepare(source, self.output)
        self.assertEqual(self.output.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
