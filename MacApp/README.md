# SBInject macOS installer

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

This directory contains the native SwiftUI front end for the repository's
one-shot installer. It launches the same pinned, reproducible
`Dopamine-CryptexBootstrap/setup.sh --install` flow used by the command line;
there is no separate GUI-only installation path.

Build the application from the repository root:

```sh
make app
open dist/SBInject.app
```

The build uses Swift 6.2 or newer, generates a complete macOS `.icns`, signs
the local application ad hoc, and writes only ignored output below `dist/` and
`MacApp/.build/`. The supplied running-pineapple artwork is retained at
`Resources/PineappleLogo.png` and is used for both the application icon and
the visible logo.

Keep the built app inside `dist/` so it finds the repository automatically.
If it is moved elsewhere, use **Choose Repository…** once, connect and unlock
a paired device, then press **Jailbreak**. A UDID is optional when exactly one
paired phone is connected.
