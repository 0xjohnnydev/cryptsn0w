#!/usr/bin/env python3
"""Host regressions, plus native IconServices method integration on macOS."""
from pathlib import Path
import json
import plistlib
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent.parent
WORKSPACE = SOURCE.parents[2]
LOGOS = WORKSPACE / "Dopamine-upstream/CryptexBootstrap/cache/lumenboard-theos/vendor/logos/bin/logos.pl"

def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)

with tempfile.TemporaryDirectory(prefix="lumenboard-tests-") as scratch:
    root = Path(scratch)
    flags = ["xcrun", "--sdk", "macosx", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-deprecated-declarations", "-framework", "Foundation", "-framework", "CoreGraphics", "-framework", "ImageIO"]
    run(*flags, SOURCE / "Tests/LMIconCacheTests.m", SOURCE / "Core/LMIconArtwork.m", SOURCE / "Shared/LMIconMapWriter.m", "-o", root / "cache-tests")
    run(root / "cache-tests", root)

    # Compile the same engine against native host classes. Runtime swizzling is
    # confined to this unprivileged test process; no system process is modified.
    fixture = root / "source"
    for name in ("Core", "Shared", "Preferences", "Tests"):
        shutil.copytree(SOURCE / name, fixture / name)
    shared = fixture / "Shared/LMShared.h"
    text = shared.read_text()
    original = '#define LMDataDirectory LMRootPath(@"/var/mobile/Library/LumenBoard")'
    assert original in text
    shared.write_text(text.replace(original, "#define LMDataDirectory @" + json.dumps(str(root))))
    text = shared.read_text()
    original = '#define LMThemesDirectory LMRootPath(@"/Library/Themes")'
    assert original in text
    shared.write_text(text.replace(original, "#define LMThemesDirectory @" + json.dumps(str(root / "themes"))))
    run(*flags, fixture / "Tests/LMThemeResourceTests.m", fixture / "Shared/LMThemeLibrary.m", fixture / "Shared/LMCCResources.m", fixture / "Shared/LMIconMapWriter.m", fixture / "Shared/LMApplyPlan.m", fixture / "Shared/LMHomeScreenOptions.m", fixture / "Preferences/LMConfigStore.m", "-o", root / "theme-tests")
    run(root / "theme-tests", root)
    generated = root / "LMIconServices.m"
    with generated.open("w") as output:
        subprocess.run(["perl", str(LOGOS), "-c", "generator=internal", str(fixture / "Core/LMIconServices.x")], stdout=output, check=True)
    app = root / "IconTest.app"
    executable = app / "Contents/MacOS/IconTest"
    executable.parent.mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.apple.Preferences", "CFBundleExecutable": "IconTest", "CFBundlePackageType": "APPL"}))
    run(*flags, "-I", fixture / "Core", fixture / "Tests/LMIconRuntimeTests.m", fixture / "Core/LMIconStore.m", fixture / "Core/LMIconArtwork.m", generated, "-o", executable)
    run(executable)
