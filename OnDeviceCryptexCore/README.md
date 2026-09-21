# On-device Cryptex core

This package creates the small Cryptex1 files that can change on an iPhone:

- `ginf`, which contains the Cryptex identifier and version
- `gtcd`, which contains the trusted CDHashes
- a BuildManifest copy with new SHA-384 digests for those two files

The package does not create a filesystem image. An iPhone app must supply one
fixed, prebuilt `gdmg` image and its matching `gtgv` volume hash. It can then
use an `idevice` RemoteXPC connection to personalize and install the five
Cryptex payloads.

This first unit does not register or launch applications. Those operations are
separate from code-signature trust and must remain outside the first install
test.

Run the tests with:

```sh
swift test --package-path OnDeviceCryptexCore
```
