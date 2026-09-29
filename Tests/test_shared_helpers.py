import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "Dopamine-CryptexBootstrap/CryptexBootstrap"
sys.path.insert(0, str(OVERLAY))
from artifact_metadata import sha256_file


class MetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="CryptSn0w-metadata-test-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.output = self.work / "summary.json"
        self.cache = self.work / "cache.binary"
        self.cache.write_bytes(b"test data")
        self.dump = self.work / "cache.txt"
        self.hashes = ["b" * 40, "a" * 40]
        self.dump.write_text("entry count = 2\n" + "".join(f"{value} 0\n" for value in self.hashes))
        self.environment = dict(os.environ, SCRIPT_DIR=str(OVERLAY),
                                IDENTIFIER="test.bundle", VERSION="1.2.3",
                                GENERATED_IMAGE_BYTES="12345")
        for key, value in {
            "SUMMARY": self.output, "BUNDLE": self.work / "bundle",
            "TRUSTCACHE": self.cache, "TRUSTCACHE_DUMP": self.dump, "ENTRY_COUNT": 2,
        }.items():
            self.environment[key] = self.environment[key.lower()] = str(value)
        self.environment["STAGE_SUMMARY"] = str(self.output)

        # Exercise the retained metadata CLI directly. The packaging
        # commands formerly inspected here are intentionally redacted.
        self.commands = [
            'python3 "$SCRIPT_DIR/artifact_metadata.py" "$SUMMARY" "$BUNDLE" "$IDENTIFIER" "$VERSION" "$TRUSTCACHE" "$TRUSTCACHE_DUMP" "$ENTRY_COUNT" --ssh-stage',
            'python3 "$SCRIPT_DIR/artifact_metadata.py" "$SUMMARY" "$BUNDLE" "$IDENTIFIER" "$VERSION" "$TRUSTCACHE" "$TRUSTCACHE_DUMP" "$ENTRY_COUNT" --image-bytes "$GENERATED_IMAGE_BYTES"',
        ]

    def test_hash_chunk_boundaries(self):
        for size in (0, 1, 1048575, 1048576, 1048577, 2097159):
            with self.subTest(size=size):
                data = b"x" * size
                self.cache.write_bytes(data)
                self.assertEqual(sha256_file(self.cache), hashlib.sha256(data).hexdigest())
        with self.assertRaises(FileNotFoundError):
            sha256_file(self.work / "missing")

    def test_both_summary_formats(self):
        for command in self.commands:
            with self.subTest(command=command):
                subprocess.run(["zsh", "-euc", command], env=self.environment,
                               cwd=self.work, check=True, timeout=10)
                expected = {
                    "identifier": "test.bundle", "version": "1.2.3",
                    "bundle": str((self.work / "bundle").resolve()),
                    "trustCache": {
                        "path": str(self.cache), "sha256": hashlib.sha256(b"test data").hexdigest(),
                        "entryCount": 2, "cdhashes": self.hashes,
                    },
                }
                expected.update({"stage": "ssh"} if "--ssh-stage" in command else {"imageBytes": 12345})
                self.assertEqual(self.output.read_bytes(),
                                 (json.dumps(expected, indent=2, sort_keys=True) + "\n").encode())

    def test_bad_counts_preserve_existing_summary(self):
        for count in ("3", "not-a-number"):
            self.environment["ENTRY_COUNT"] = self.environment["entry_count"] = count
            for command in self.commands:
                with self.subTest(count=count, command=command):
                    self.output.write_text("previous summary")
                    result = subprocess.run(["zsh", "-euc", command], env=self.environment,
                                            cwd=self.work, capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.output.read_text(), "previous summary")
                    if count == "3":
                        prefix = b"stage " if "--ssh-stage" in command else b""
                        self.assertEqual(result.stderr, prefix + b"trust-cache count mismatch\n")


@unittest.skipUnless(sys.platform == "darwin", "requires the local C compiler")
class IOTests(unittest.TestCase):
    def test_shared_io(self):
        with tempfile.TemporaryDirectory(prefix="CryptSn0w-io-test-") as directory:
            executable = Path(directory) / "io-test"
            subprocess.run([
                "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(OVERLAY), str(ROOT / "Tests/io_helpers_test.c"),
                "-o", str(executable),
            ], check=True, timeout=30)
            subprocess.run([str(executable)], check=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
