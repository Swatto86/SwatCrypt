SwatCrypt file format (v1)
==========================

Overview
--------

Content is sealed with `XChaCha20-Poly1305` using the STREAM construction (BE32 counters). Key material comes from `Argon2id`. The header is plaintext but authenticated as AAD. All file metadata (manifest) lives inside the ciphertext.

Layout
------

```
offset  size  description
0       4     magic = "SWC1"
4       1     version = 1
5       1     cipher id (1 = XChaCha20-Poly1305)
6       1     kdf id (1 = Argon2id)
7       1     reserved (0)
8       4     flags (bit0=bundle, bit1=compressed)
12      4     chunk_size (u32 LE, plaintext chunk size)
16      4     kdf_mem_mib (u32 LE)
20      4     kdf_iterations (u32 LE)
24      4     kdf_parallelism (u32 LE)
28      2     salt_len (u16 LE)
30      2     nonce_len (u16 LE)
32      salt  random salt for KDF
...     nonce STREAM base nonce (19 bytes for XChaCha STREAM)
...     ciphertext (STREAM chunks, each chunk_size + 16 tag, last chunk shorter)
```

Plaintext before encryption
---------------------------

```
manifest_len (u32 LE)
manifest JSON (serde):
  {
    "version": 1,
    "bundle": bool,
    "compression": bool,
    "entries": [
      { "path": "root/file.txt", "size": 1234, "is_dir": false },
      { "path": "root/subdir",    "size": 0,    "is_dir": true  }
    ]
  }
tar stream (relative paths from manifest)
```

Flags
-----
- bit0: bundle (true if multiple inputs or a directory was encrypted)
- bit1: compressed (plaintext tar was gzip-compressed before encryption)

Security notes
--------------
- Header is authenticated (AAD) so tampering with parameters breaks decryption.
- Symlinks are rejected during archive creation to avoid unexpected writes.
- Chunk size is bounded in code (`4 KiB` - `2 MiB`) and stored in header for forward compatibility.

Defaults
--------
- cipher: XChaCha20-Poly1305
- chunk size: 64 KiB plaintext per STREAM chunk
- KDF: Argon2id mem=64 MiB, iters=3, parallelism=1
- Compression: off by default
