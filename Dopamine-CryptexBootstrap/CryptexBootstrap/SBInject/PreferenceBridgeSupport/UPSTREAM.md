# PreferenceLoader bridge support

The files in this directory are copied verbatim from
[`Yves000/preferenceloader`](https://github.com/Yves000/preferenceloader) at
commit `65f329368772d084c9313f9273bff1744658e185` (release `2.3.3`):

- `PLHeap.h` / `PLHeap.m`
- `PLSwiftMeta.h` / `PLSwiftMeta.m`
- `PLSwiftString.swift`

They provide the generic Swift-metadata, heap-discovery, and `String` helpers
used by the local iOS 27 Settings bridge. The upstream `LICENSE` is retained
beside them. Keeping these small source files in-tree makes the build
reproducible without installing Theos or fetching source during a Cryptex
build.
