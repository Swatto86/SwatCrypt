SwatCrypt
=========

XChaCha20-Poly1305 + Argon2id file encryption for personal use. A single `.swc` file can wrap one or many files/folders while preserving relative paths. Defaults:

- Cipher: `XChaCha20-Poly1305` (STREAM).
- KDF: `Argon2id` (`mem=64 MiB`, `iters=3`, `parallelism=1`).
- Bundles multiple selections; optional gzip compression (off by default).
- Tamper detection via AEAD; symlinks are rejected.

Quick start
-----------
```
cargo run                                                      # launch GUI (no args)
cargo run -- encrypt path/to/file.txt                          # CLI encrypt (with args)
cargo run -- decrypt path/to/file.swc                          # CLI decrypt
cargo run -- info path/to/file.swc                             # CLI header info
```

Project layout
--------------
- Single crate: `src/lib.rs` (core crypto + format) and `src/main.rs` (GUI + CLI entry).
- Build script: `build.rs` generates/embeds the app icon on Windows.

GUI notes
---------
- Multi-file/folder selection, bundles by default.
- Optional gzip compression.
- Passphrase with confirm (required); no keyring storage.
- Live progress updates; verify-decrypt-before-wipe option when wiping originals.
- Defaults: `<input>.swc` or `bundle.swc` on encrypt, `<cipher>_dec/` on decrypt.
- Red lock app icon; `swatcrypt.exe` embeds the icon on Windows.
- Status appears at the bottom of the window (beneath Integration) with progress when busy.

Windows Explorer context menus
------------------------------
- In-app toggle (Windows only): open the GUI > Integration > Install/Remove. No admin needed (HKCU keys only).
- Adds "Decrypt with SwatCrypt" (for `.swc`) and "Open in SwatCrypt" (launches GUI pre-filled with your selection).
- Use the GUI or CLI directly for encryption (no Explorer encrypt verb).

CLI flags (via `swatcrypt`)
---------------------------
- `encrypt`: `--output <file>` (default: `<input>.swc` or `bundle.swc`), `--compress`, `--passphrase <pw>`, `--chunk-size <bytes>`, `--force`, `--wipe`.
- `decrypt`: `--output <dir>` (default: `<cipher_stem>_dec` beside the cipher), `--passphrase`, `--force`.
- `info`: read header/KDF/cipher flags without decrypting.
- Progress: CLI shows a bar during encrypt/decrypt; GUI shows inline progress.

Format sketch
-------------
- Header (plaintext, authenticated as AAD): magic `SWC1`, version `1`, flags (bundle, compressed), chunk size, cipher id, KDF id + params, salt len, nonce len.
- Body: salt || nonce || STREAM-encrypted payload using header as AAD.
- Plaintext payload: `manifest_len (u32 LE) || manifest JSON || tar stream` (optionally gzip-compressed).
- Manifest entries hold relative paths (rooted at each selected item name), file sizes, and dir markers.

Packaging
---------
- Build release: `cargo build --release` -> `target/release/swatcrypt.exe` (Windows) or `swatcrypt` (Unix). Icon generated/embedded at build time on Windows.
