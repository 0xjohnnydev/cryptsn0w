// Keep Sileo's upstream libzstd dependency separate from the root-broker
// constructor. The actual zstd symbols are re-exported by the linker; this
// anchor only gives clang a translation unit for the shim.
__attribute__((visibility("hidden"))) void
codex_sileo_zstd_reexport_anchor(void) {}
