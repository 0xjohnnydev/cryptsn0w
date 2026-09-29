import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin", "requires macOS Foundation")
class ManagedFileTests(unittest.TestCase):
    def test_installation_and_backup(self):
        source = (ROOT / "Dopamine-CryptexBootstrap/CryptexBootstrap/codex_dopamine_bootstrap.m").read_text()
        functions = []
        for signature in (
            "static bool files_are_equal(NSString *left, NSString *right) {",
            "static bool install_managed_apt_file(NSString *source, NSString *directory,",
            "static bool replace_file_with_backup(NSString *source, NSString *destination,",
            "static bool restore_packaged_tool(NSString *source, NSString *destination,",
        ):
            start = source.index(signature)
            end = source.index("\n}\n", start) + 3
            functions.append(source[start:end])
        harness = (ROOT / "Tests/managed_file_test.m").read_text()
        with tempfile.TemporaryDirectory(prefix="CryptSn0w-file-test-") as directory:
            work = pathlib.Path(directory)
            test_source = work / "test.m"
            executable = work / "test"
            test_source.write_text(harness.replace("// PRODUCTION_FUNCTIONS", "\n".join(functions)))
            subprocess.run([
                "xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation", str(test_source), "-o", str(executable),
            ], check=True, timeout=30)
            subprocess.run([str(executable), directory], check=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
