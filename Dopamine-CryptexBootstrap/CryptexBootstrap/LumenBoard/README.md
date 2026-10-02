# ☆ Rebug for Settings

Vendored from [xsxs18-dev/LumenBoard](https://github.com/xsxs18-dev/LumenBoard)
at the commit recorded in `UPSTREAM.json`. The upstream MIT license is in
`LICENSE`.

This fork builds the icon engine and a PreferenceLoader bundle. Open
**Settings > ☆ Rebug** to select and reorder themes, set appearance options, and
apply changes. English and German resources load from the preference bundle.
Existing theme selections and preferences are preserved; generated icon maps
use version 3. No standalone application is built or registered.

The supplied Rebug logo appears above the theme list. Category filters, previews,
dynamic text, a fixed Apply button, and grouped Appearance controls support
light and dark mode. The internal package and bundle identifiers remain
LumenBoard for upgrade compatibility and upstream attribution.

**Hide dock background only** is directly below the logo on the main pane, with
an **Apply dock only** button below the option. It is also available in
**Appearance > Home Screen**. It defaults
to off. Toggle it and tap Apply changes to update the normal or floating dock background;
disabling it and applying restores the background. Dock icons remain visible.
This built-in visibility option does not add support for dock artwork packs.

**Apply dock only** on the main pane or in Appearance applies just the dock switch immediately and
shows a completion sheet without respringing. It writes a separate applied
`DockOptions.plist` and notifies only the dock background views. The icon map,
generation, skipped items, theme selection, and label settings are unchanged;
any queued changes remain pending across restarts. A later full Apply includes
the dock switch with all other changes.

**Hide icon labels** is beside the dock switch under Home Screen. It
defaults to off. Turn it on and tap Apply changes to hide Home
Screen app and folder names while keeping the current icon size and spacing,
including Small mode. Turning it off and applying restores native visibility.
The hook changes only the label child of Home Screen icon views; it does not
change the native icon-size preference, app names, or App Library/search labels.

Themes live in `/var/jb/Library/Themes`; configuration remains in
`/var/jb/var/mobile/Library/LumenBoard`.

The parent build includes the package and an identical signed payload in the
research cryptex. Updates to this fixed version require rebuilding the cryptex.
The fork renders app icons locally in SpringBoard and Settings, since this
bootstrap runs the stock icon service. Other clients still need the upstream
renderer. Missing dark or tinted artwork uses the theme's light PNG; the local
iOS-shape option uses a rounded mask.

The picker filters packs into Apps, CC, Shapes, and Other by their contents:

- Apps: bundle-ID PNGs in `IconBundles`, and app-name PNGs in `Icons`.
  Catalogue `Icon.png`, `Preview.png`, and `Thumbnail.png` in `IconBundles`
  are excluded.
- CC: named PNG resources in `Bundles/<bundle identifier>`, shared media
  glyphs in `UIImages`, and mirrored PNG paths in `Folders`. Bundle, scale,
  device, and appearance suffixes are normalized. Requests are routed in
  SpringBoard through UIKit's named image APIs, scoped SF Symbol aliases,
  and available `CCUIToggleModule` image/package getters. This includes the
  installed Glif add-on's connectivity and flashlight names. Unmatched
  resources retain their original artwork; this does not convert arbitrary
  vector or animated packages or promise compatibility with every third-party
  CC implementation.
- Shapes: `AppIconMask` in `Bundles/com.apple.mobileicons.framework` or
  `UIImages`, plus `iPhone`/`iPad` Underlay, Shadow, and Overlay PNGs in
  `AnemoneEffects`. Layers can decorate an app pack or original app artwork.
  Turn off **iOS icon shape** to use a custom mask.
- Other: resource packs without supported artwork, including respring
  animations, badges, and dock artwork. The picker identifies them as unsupported.

App icons, CC glyphs, and effect packs can be enabled together. The first active
theme containing each resource wins, and reordering within a category preserves
the positions of hidden themes.

Apply and Clear Cache rotate artwork tokens and discard decoded app artwork.
Invalid images are filtered before rendering so one bad mask cannot break all
apps. If some items succeed and others fail, **Continue applying** commits the
good entries, records the skipped items, and resprings. A continuation must match
the same generation and selection; it cannot commit a newer attempt. The pane
shows the skipped count after completion. Apply retries the original selection,
including skipped entries. A respring preserves an accepted partial map.
Fatal writes and attempts without any successful items do not offer Continue.
CC preflight checks decoded artwork and client availability; checking every
actual Control Center module and the Settings UI on the target OS still requires
a device smoke test after updating the Cryptex.

Build separately with the parent's `build_lumenboard.py`, or with Theos:

```sh
THEOS=/path/to/theos make clean package
```

Use Logos commit `a62370066a97e36d59b200a9fa10c5091f5e8972`, as in upstream.
The small Preferences linker stub declares only the pane's superclass for SDKs
that omit the private framework. It is a build input and is not packaged.

From the workspace root, `make test-lumenboard` checks theme categories and
resource priority, CC request names, image generations, replacement PNGs,
custom masks and effect composition, corrupt artwork, partial commits,
selection/generation guards, retry after skips, and dock/label visibility
configuration migration, persistence, and restoration. Dock-only regression
checks preserve the map and saved configuration byte-for-byte and keep pending
themes and labels separate, including startup before the first icon map.
Native synchronous and
asynchronous IconServices integration runs in a separate host process using
the cached Logos toolchain. Stock-effect integration uses a controlled native
image fixture; host-service placeholders are rejected as incomplete artwork.
