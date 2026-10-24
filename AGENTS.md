# SwatCrypt

Personal file encryption: one `.swc` file wraps one or many files and folders, keeping relative paths, sealed with
XChaCha20-Poly1305 (STREAM) under an Argon2id key from a passphrase. One Rust crate gives both an egui/eframe GUI
(no arguments) and a clap CLI (`encrypt`, `decrypt`, `info`). It builds on Windows and Unix; Explorer integration and
the released binaries are Windows x64 only. Public repository `Swatto86/SwatCrypt`, single branch `main`, latest
release v1.0.0, MIT.

## Build, test, verify

- `cargo build --release` gives `target/release/swatcrypt.exe` (or `swatcrypt` on Unix). This is the only check the
  repository runs, and only in `release.yml`. There is no CI on push.
- There is no test suite. Verify a change by round trip: `cargo run -- encrypt <path>`, `cargo run -- decrypt
  <path>.swc`, then compare the output; `cargo run -- info <file>.swc` reads the header without decrypting.
  `cargo run` with no arguments starts the GUI.
- Release builds on Windows use the GUI subsystem (`windows_subsystem = "windows"`) and have no console; debug builds
  keep one.

## Release

- The version is in `Cargo.toml`. Pushing a `v*` tag runs `release.yml` on `windows-latest`: `cargo build --release`,
  then NSIS from `.github/installer.nsi`, publishing `SwatCrypt_<ver>_x64-portable.exe` and
  `SwatCrypt_<ver>_x64-setup.exe` (per-machine install under Program Files, needs admin). Publishing is Swatto's call.

## Where things are

- `src/lib.rs`: header, KDF, STREAM encrypt/decrypt, manifest and tar bundling, extraction checks, secure wipe.
- `src/main.rs`: GUI, CLI and the Windows Explorer integration (HKCU only).
- `build.rs`: draws the red lock icon and embeds it on Windows. `assets/icon.ico` is not referenced.
- `docs/FORMAT.md`: the v1 byte layout.

## Constraints

- The `.swc` format is a compatibility contract: every file already written must keep decrypting. Magic `SWC1`,
  version `1`, cipher and KDF ids, flags, KDF parameters, salt and nonce lengths, the header-as-AAD rule and the
  `manifest_len || manifest JSON || tar` payload are fixed for v1. Any format change needs Swatto's agreement, a new
  version and continued v1 decryption, and `docs/FORMAT.md` updated with it.
- Defaults in force: Argon2id 64 MiB, 3 iterations, parallelism 1; 64 KiB chunks (bounded 4 KiB to 2 MiB); manifest
  at most 8 MiB; gzip compression off.
- Safety behaviour to keep: symlinks are rejected when bundling; extraction refuses absolute paths and `..`; encrypt
  will not replace an existing output and decrypt will not write into a non-empty folder without `--force`; the GUI
  verifies by decrypting before it wipes originals (on by default). Wipe is best effort: one pass of random bytes,
  truncate, delete.
- `unsafe_code = "forbid"`. Key material and secrets are held in `Zeroizing` buffers. Passphrases are never stored;
  there is no keyring.
- Explorer integration writes only under `HKCU\Software\Classes`: "Decrypt with SwatCrypt" for `.swc` and "Open in
  SwatCrypt" for any file. There is deliberately no Explorer encrypt verb; install removes a legacy one.
- The GUI is single-instance. A second launch with paths hands them to the running window through
  `%TEMP%\swatcrypt_gui_launch_queue.jsonl`.

## Open questions

- The Explorer verb runs `swatcrypt decrypt "%1"`. The CLI asks for the passphrase on a console (rpassword), but a
  release build has no console. How that verb gets a passphrase is not established from the code.
- The library supports keyfiles (`keyfile` on the requests, `generate_keyfile`), but neither the CLI nor the GUI
  exposes them.

## Where longer material lives

- `README.md`: usage, GUI notes, CLI flags, format sketch.
- `docs/FORMAT.md`: the file format. There is no `ARCHITECTURE.md` or `CONTEXT.md`.
