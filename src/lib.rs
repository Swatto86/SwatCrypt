use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use bytes::BufMut;
use chacha20poly1305::{
    aead::{
        stream::{DecryptorBE32, EncryptorBE32},
        KeyInit, OsRng, Payload,
    },
    Key, XChaCha20Poly1305,
};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tar::Archive;
use thiserror::Error;
use walkdir::WalkDir;
use zeroize::Zeroizing;

pub const EXTENSION: &str = "swc";

const MAGIC: &[u8; 4] = b"SWC1";
const VERSION: u8 = 1;
const FLAG_BUNDLE: u32 = 0x01;
const FLAG_COMPRESSED: u32 = 0x02;
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
const MIN_CHUNK_SIZE: usize = 4 * 1024;
const MAX_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const MAX_MANIFEST_SIZE: u32 = 8 * 1024 * 1024;
const KEY_LEN: usize = 32;

type StreamNonce = chacha20poly1305::aead::stream::Nonce<
    XChaCha20Poly1305,
    chacha20poly1305::aead::stream::StreamBE32<XChaCha20Poly1305>,
>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("no input paths provided")]
    NoInputs,
    #[error("a passphrase or keyfile is required")]
    MissingSecret,
    #[error("input path not found: {0}")]
    MissingPath(String),
    #[error("unsupported file type at {0}")]
    UnsupportedPath(String),
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("invalid format: {0}")]
    Format(String),
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Argon(#[from] argon2::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Walkdir(#[from] walkdir::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Clone, Copy)]
pub enum CipherSuite {
    XChaCha20Poly1305 = 1,
}

impl CipherSuite {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::XChaCha20Poly1305),
            _ => Err(CoreError::InvalidHeader("unknown cipher")),
        }
    }

    fn tag_len(&self) -> usize {
        16
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KdfKind {
    Argon2id = 1,
}

impl KdfKind {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::Argon2id),
            _ => Err(CoreError::InvalidHeader("unknown kdf")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KdfConfig {
    pub mem_mib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            mem_mib: 64,
            iterations: 3,
            parallelism: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressStage {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub stage: ProgressStage,
    pub processed: u64,
    pub total: Option<u64>,
}

pub type ProgressCallback = Box<dyn FnMut(ProgressUpdate) + Send>;

pub struct EncryptRequest {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
    pub passphrase: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub compression: bool,
    pub chunk_size: Option<usize>,
    pub kdf: KdfConfig,
    pub progress: Option<ProgressCallback>,
}

impl EncryptRequest {
    pub fn normalized_chunk_size(&self) -> Result<usize> {
        let sz = self.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        if sz < MIN_CHUNK_SIZE || sz > MAX_CHUNK_SIZE {
            return Err(CoreError::Format("chunk size out of bounds".into()));
        }
        Ok(sz)
    }
}

pub struct DecryptRequest {
    pub input: PathBuf,
    pub output_dir: PathBuf,
    pub passphrase: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub overwrite: bool,
    pub progress: Option<ProgressCallback>,
}

#[derive(Debug, Clone)]
pub struct EncryptResult {
    pub output: PathBuf,
    pub bundle: bool,
    pub compressed: bool,
    pub manifest_entries: usize,
    pub bytes_written: u64,
}

#[derive(Debug, Clone)]
pub struct DecryptResult {
    pub output_dir: PathBuf,
    pub manifest_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub bundle: bool,
    pub compression: bool,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone)]
pub struct HeaderInfo {
    pub cipher: CipherSuite,
    pub kdf: KdfKind,
    pub flags: u32,
    pub chunk_size: usize,
    pub kdf_params: KdfConfig,
    pub salt_len: usize,
    pub nonce_len: usize,
}

#[derive(Debug, Clone)]
struct Header {
    flags: u32,
    chunk_size: u32,
    cipher: CipherSuite,
    kdf: KdfKind,
    kdf_params: KdfConfig,
    salt_len: u16,
    nonce_len: u16,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(MAGIC);
        buf.push(VERSION);
        buf.push(self.cipher as u8);
        buf.push(self.kdf as u8);
        buf.push(0); // reserved
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.chunk_size.to_le_bytes());
        buf.extend_from_slice(&self.kdf_params.mem_mib.to_le_bytes());
        buf.extend_from_slice(&self.kdf_params.iterations.to_le_bytes());
        buf.extend_from_slice(&self.kdf_params.parallelism.to_le_bytes());
        buf.extend_from_slice(&self.salt_len.to_le_bytes());
        buf.extend_from_slice(&self.nonce_len.to_le_bytes());
        buf
    }

    fn decode<R: Read>(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(CoreError::InvalidHeader("bad magic"));
        }
        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(CoreError::InvalidHeader("unsupported version"));
        }
        let mut tmp = [0u8; 1];
        reader.read_exact(&mut tmp)?;
        let cipher = CipherSuite::from_byte(tmp[0])?;
        reader.read_exact(&mut tmp)?;
        let kdf = KdfKind::from_byte(tmp[0])?;
        reader.read_exact(&mut tmp)?; // reserved

        let flags = read_u32(&mut reader)?;
        let chunk_size = read_u32(&mut reader)?;
        let mem_mib = read_u32(&mut reader)?;
        let iterations = read_u32(&mut reader)?;
        let parallelism = read_u32(&mut reader)?;
        let salt_len = read_u16(&mut reader)?;
        let nonce_len = read_u16(&mut reader)?;

        Ok(Self {
            flags,
            chunk_size,
            cipher,
            kdf,
            kdf_params: KdfConfig {
                mem_mib,
                iterations,
                parallelism,
            },
            salt_len,
            nonce_len,
        })
    }

    fn info(&self) -> HeaderInfo {
        HeaderInfo {
            cipher: self.cipher,
            kdf: self.kdf,
            flags: self.flags,
            chunk_size: self.chunk_size as usize,
            kdf_params: self.kdf_params.clone(),
            salt_len: self.salt_len as usize,
            nonce_len: self.nonce_len as usize,
        }
    }
}

pub fn encrypt(req: EncryptRequest) -> Result<EncryptResult> {
    if req.inputs.is_empty() {
        return Err(CoreError::NoInputs);
    }
    let chunk_size = req.normalized_chunk_size()?;

    let mut progress_cb = req.progress;
    let secret = gather_secret(req.passphrase.as_deref(), req.keyfile.as_deref())?;

    let (mut manifest, tar_file) = build_tar(&req.inputs)?;
    let tar_len = tar_file.metadata()?.len();
    manifest.compression = req.compression;

    let (mut plaintext_file, payload_len) = if req.compression {
        let mut compressed = tempfile::tempfile()?;
        {
            let mut encoder = GzEncoder::new(&mut compressed, Compression::default());
            let mut reader = BufReader::new(tar_file);
            io::copy(&mut reader, &mut encoder)?;
            encoder.finish()?;
        }
        compressed.rewind()?;
        let compressed_len = compressed.metadata()?.len();
        (compressed, compressed_len)
    } else {
        let mut file = tar_file;
        file.rewind()?;
        (file, tar_len)
    };

    let manifest_bytes = serde_json::to_vec(&manifest)?;
    if manifest_bytes.len() as u32 > MAX_MANIFEST_SIZE {
        return Err(CoreError::Format("manifest too large".into()));
    }
    let total_plain = 4u64 + manifest_bytes.len() as u64 + payload_len;
    report_progress(
        &mut progress_cb,
        ProgressStage::Encrypt,
        0,
        Some(total_plain),
    );

    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut base_nonce = vec![0u8; StreamNonce::default().len()];
    OsRng.fill_bytes(&mut base_nonce);

    let key = derive_key(&secret, &salt, &manifest, &req.kdf)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let stream_nonce = StreamNonce::clone_from_slice(&base_nonce);
    let mut encryptor = Some(EncryptorBE32::from_aead(cipher, &stream_nonce));

    let flags = build_flags(&manifest);
    let header = Header {
        flags,
        chunk_size: chunk_size as u32,
        cipher: CipherSuite::XChaCha20Poly1305,
        kdf: KdfKind::Argon2id,
        kdf_params: req.kdf.clone(),
        salt_len: salt.len() as u16,
        nonce_len: base_nonce.len() as u16,
    };

    if let Some(parent) = req.output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut out = BufWriter::new(File::create(&req.output)?);
    let header_bytes = header.encode();
    out.write_all(&header_bytes)?;
    out.write_all(&salt)?;
    out.write_all(&base_nonce)?;

    let aad = header_bytes;
    let mut bytes_written: u64 =
        (MAGIC.len() + 1 + 3 + 4 * 5 + 2 + 2 + salt.len() + base_nonce.len()) as u64;

    let mut buffer = vec![0u8; chunk_size];
    let mut prefix = Vec::with_capacity(4 + manifest_bytes.len());
    prefix.put_u32_le(manifest_bytes.len() as u32);
    prefix.extend_from_slice(&manifest_bytes);
    let mut prefix_cursor = io::Cursor::new(prefix);
    let mut processed: u64 = 0;

    loop {
        let mut filled = 0usize;

        if prefix_cursor.position() < prefix_cursor.get_ref().len() as u64 {
            filled = prefix_cursor.read(&mut buffer)?;
        }

        if filled < buffer.len() {
            let read_more = plaintext_file.read(&mut buffer[filled..])?;
            filled += read_more;
        }

        if filled == 0 {
            break;
        }

        let payload = Payload {
            msg: &buffer[..filled],
            aad: &aad,
        };

        if filled < chunk_size {
            let encryptor = encryptor.take().ok_or(CoreError::Encrypt)?;
            let ciphertext = encryptor
                .encrypt_last(payload)
                .map_err(|_| CoreError::Encrypt)?;
            out.write_all(&ciphertext)?;
            bytes_written += ciphertext.len() as u64;
        } else {
            let encryptor = encryptor.as_mut().ok_or(CoreError::Encrypt)?;
            let ciphertext = encryptor
                .encrypt_next(payload)
                .map_err(|_| CoreError::Encrypt)?;
            out.write_all(&ciphertext)?;
            bytes_written += ciphertext.len() as u64;
        }
        processed += filled as u64;
        report_progress(
            &mut progress_cb,
            ProgressStage::Encrypt,
            processed,
            Some(total_plain),
        );
        if filled < chunk_size {
            break;
        }
    }

    out.flush()?;

    Ok(EncryptResult {
        output: req.output,
        bundle: (flags & FLAG_BUNDLE) != 0,
        compressed: (flags & FLAG_COMPRESSED) != 0,
        manifest_entries: manifest.entries.len(),
        bytes_written,
    })
}

pub fn decrypt(req: DecryptRequest) -> Result<DecryptResult> {
    if !req.input.exists() {
        return Err(CoreError::MissingPath(req.input.display().to_string()));
    }

    let mut progress_cb = req.progress;
    let total_len = fs::metadata(&req.input)?.len();
    report_progress(&mut progress_cb, ProgressStage::Decrypt, 0, Some(total_len));
    let mut reader = BufReader::new(File::open(&req.input)?);
    let header = Header::decode(&mut reader)?;
    let chunk_size = header.chunk_size as usize;
    if chunk_size < MIN_CHUNK_SIZE || chunk_size > MAX_CHUNK_SIZE {
        return Err(CoreError::InvalidHeader("chunk size out of bounds"));
    }

    let mut salt = vec![0u8; header.salt_len as usize];
    reader.read_exact(&mut salt)?;
    let mut base_nonce = vec![0u8; header.nonce_len as usize];
    reader.read_exact(&mut base_nonce)?;

    let secret = gather_secret(req.passphrase.as_deref(), req.keyfile.as_deref())?;
    let manifest_hint = Manifest {
        version: VERSION,
        bundle: (header.flags & FLAG_BUNDLE) != 0,
        compression: (header.flags & FLAG_COMPRESSED) != 0,
        entries: Vec::new(),
    };
    let key = derive_key(&secret, &salt, &manifest_hint, &header.kdf_params)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = StreamNonce::clone_from_slice(&base_nonce);
    let mut decryptor = Some(DecryptorBE32::from_aead(cipher, &nonce));

    let mut plaintext_tmp = tempfile::tempfile()?;
    let mut buffer = vec![0u8; chunk_size + CipherSuite::XChaCha20Poly1305.tag_len()];
    let aad_header = header.encode();
    let mut processed = reader.stream_position().unwrap_or(0);
    report_progress(
        &mut progress_cb,
        ProgressStage::Decrypt,
        processed,
        Some(total_len),
    );

    loop {
        let read_len = reader.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }
        if read_len < buffer.len() {
            let decryptor = decryptor.take().ok_or(CoreError::Decrypt)?;
            let plaintext = decryptor
                .decrypt_last(Payload {
                    msg: &buffer[..read_len],
                    aad: &aad_header,
                })
                .map_err(|_| CoreError::Decrypt)?;
            plaintext_tmp.write_all(&plaintext)?;
            break;
        } else {
            let decryptor = decryptor.as_mut().ok_or(CoreError::Decrypt)?;
            let plaintext = decryptor
                .decrypt_next(Payload {
                    msg: &buffer[..read_len],
                    aad: &aad_header,
                })
                .map_err(|_| CoreError::Decrypt)?;
            plaintext_tmp.write_all(&plaintext)?;
        }
        processed += read_len as u64;
        report_progress(
            &mut progress_cb,
            ProgressStage::Decrypt,
            processed,
            Some(total_len),
        );
    }

    plaintext_tmp.rewind()?;

    let mut final_plain = if (header.flags & FLAG_COMPRESSED) != 0 {
        let mut inflated = tempfile::tempfile()?;
        let mut decoder = GzDecoder::new(&mut plaintext_tmp);
        io::copy(&mut decoder, &mut inflated)?;
        inflated.rewind()?;
        inflated
    } else {
        plaintext_tmp
    };

    let manifest_len = read_u32(&mut final_plain)?;
    if manifest_len > MAX_MANIFEST_SIZE {
        return Err(CoreError::Format("manifest length is unrealistic".into()));
    }
    let mut manifest_buf = vec![0u8; manifest_len as usize];
    final_plain.read_exact(&mut manifest_buf)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_buf)?;

    if manifest.bundle != ((header.flags & FLAG_BUNDLE) != 0) {
        return Err(CoreError::Format("bundle flag mismatch".into()));
    }

    if !req.output_dir.exists() {
        fs::create_dir_all(&req.output_dir)?;
    } else if !req.overwrite && req.output_dir.read_dir()?.next().is_some() {
        return Err(CoreError::Format(format!(
            "output dir {} is not empty (use --force/overwrite)",
            req.output_dir.display()
        )));
    }

    let offset = 4 + manifest_len as u64;
    final_plain.seek(SeekFrom::Start(offset))?;
    extract_tar(final_plain, &req.output_dir)?;

    Ok(DecryptResult {
        output_dir: req.output_dir,
        manifest_entries: manifest.entries.len(),
    })
}

pub fn inspect_header(path: &Path) -> Result<HeaderInfo> {
    let mut reader = BufReader::new(File::open(path)?);
    let header = Header::decode(&mut reader)?;
    Ok(header.info())
}

fn build_flags(manifest: &Manifest) -> u32 {
    let mut f = 0u32;
    if manifest.bundle {
        f |= FLAG_BUNDLE;
    }
    if manifest.compression {
        f |= FLAG_COMPRESSED;
    }
    f
}

fn build_tar(inputs: &[PathBuf]) -> Result<(Manifest, File)> {
    let mut entries = Vec::new();
    let mut builder = tar::Builder::new(tempfile::tempfile()?);
    builder.follow_symlinks(false);
    let mut bundle = inputs.len() > 1;

    for path in inputs {
        if !path.exists() {
            return Err(CoreError::MissingPath(path.display().to_string()));
        }
        let meta = fs::metadata(path)?;
        let root_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("root")
            .to_string();

        if meta.is_dir() {
            bundle = true;
            for entry in WalkDir::new(path).into_iter() {
                let entry = entry?;
                let file_type = entry.file_type();
                if file_type.is_symlink() {
                    return Err(CoreError::UnsupportedPath(format!(
                        "symlinks are not supported: {}",
                        entry.path().display()
                    )));
                }

                let rel = entry
                    .path()
                    .strip_prefix(path)
                    .unwrap_or(entry.path())
                    .to_path_buf();
                let mut name = PathBuf::from(&root_name);
                if !rel.as_os_str().is_empty() {
                    name.push(rel);
                }
                let name_str = normalize_path(&name);

                if file_type.is_dir() {
                    entries.push(ManifestEntry {
                        path: name_str,
                        size: 0,
                        is_dir: true,
                    });
                    builder.append_dir(name, entry.path())?;
                } else if file_type.is_file() {
                    let size = entry.metadata()?.len();
                    entries.push(ManifestEntry {
                        path: name_str,
                        size,
                        is_dir: false,
                    });
                    builder.append_path_with_name(entry.path(), &name)?;
                }
            }
        } else if meta.is_file() {
            let name = PathBuf::from(&root_name);
            let size = meta.len();
            entries.push(ManifestEntry {
                path: normalize_path(&name),
                size,
                is_dir: false,
            });
            builder.append_path_with_name(path, name)?;
        } else {
            return Err(CoreError::UnsupportedPath(path.display().to_string()));
        }
    }

    builder.finish()?;
    let mut file = builder.into_inner()?;
    file.rewind()?;

    let manifest = Manifest {
        version: VERSION,
        bundle,
        compression: false,
        entries,
    };
    Ok((manifest, file))
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn secure_wipe_paths(paths: &[PathBuf]) -> Result<()> {
    let mut dirs = Vec::new();

    for path in paths {
        if !path.exists() {
            continue;
        }
        let meta = fs::metadata(path)?;
        if meta.is_file() {
            wipe_file(path)?;
        } else if meta.is_dir() {
            dirs.push(path.to_path_buf());
            for entry in WalkDir::new(path).into_iter() {
                let entry = entry?;
                let ft = entry.file_type();
                if ft.is_file() {
                    wipe_file(entry.path())?;
                } else if ft.is_dir() {
                    dirs.push(entry.path().to_path_buf());
                }
            }
        }
    }

    // Remove directories deepest-first (best effort; ignore failures)
    dirs.sort_by_key(|p| p.components().count());
    dirs.dedup();
    for dir in dirs.into_iter().rev() {
        let _ = fs::remove_dir(&dir);
    }
    Ok(())
}

fn wipe_file(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(());
    }
    let len = meta.len();
    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(buf.len() as u64) as usize;
        OsRng.fill_bytes(&mut buf[..chunk]);
        file.write_all(&buf[..chunk])?;
        remaining -= chunk as u64;
    }
    file.flush()?;
    let _ = file.sync_all();
    file.set_len(0)?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

fn report_progress(
    cb: &mut Option<ProgressCallback>,
    stage: ProgressStage,
    processed: u64,
    total: Option<u64>,
) {
    if let Some(cb) = cb.as_mut() {
        cb(ProgressUpdate {
            stage,
            processed,
            total,
        });
    }
}

fn derive_key(
    secret: &Zeroizing<Vec<u8>>,
    salt: &[u8],
    manifest: &Manifest,
    kdf: &KdfConfig,
) -> Result<Zeroizing<Vec<u8>>> {
    let mem_kib = kdf
        .mem_mib
        .checked_mul(1024)
        .ok_or_else(|| CoreError::Format("kdf memory too large".into()))?;
    let params = Params::new(mem_kib, kdf.iterations, kdf.parallelism, None)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    let mut material = Zeroizing::new(Vec::with_capacity(secret.len() + 16));
    material.extend_from_slice(secret);
    // include manifest version to make tweaks distinct
    material.push(manifest.version);
    argon.hash_password_into(&material, salt, &mut key)?;
    Ok(key)
}

pub fn generate_keyfile(path: &Path, force: bool, length: Option<usize>) -> Result<PathBuf> {
    let len = length.unwrap_or(KEY_LEN);
    if len == 0 || len > 4096 {
        return Err(CoreError::Format(
            "keyfile length must be between 1 and 4096 bytes".into(),
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    if path.exists() && !force {
        return Err(CoreError::Format(format!(
            "keyfile {} already exists (use force to overwrite)",
            path.display()
        )));
    }
    let mut data = vec![0u8; len];
    OsRng.fill_bytes(&mut data);

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let mut file = opts.open(path)?;
    file.write_all(&data)?;
    file.flush()?;
    Ok(path.to_path_buf())
}

fn gather_secret(passphrase: Option<&str>, keyfile: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    if passphrase.is_none() && keyfile.is_none() {
        return Err(CoreError::MissingSecret);
    }
    let mut secret = Zeroizing::new(Vec::new());
    if let Some(pw) = passphrase {
        secret.extend_from_slice(pw.as_bytes());
    }
    if let Some(path) = keyfile {
        let data = fs::read(path)?;
        secret.extend_from_slice(&data);
    }
    Ok(secret)
}

fn read_u16<R: Read>(r: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn extract_tar<R: Read>(reader: R, output_dir: &Path) -> Result<()> {
    let mut archive = Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let path = path.as_ref();

        if path.is_absolute() || path.components().any(|c| c.as_os_str() == "..") {
            return Err(CoreError::Format(format!(
                "refusing to extract suspicious path {:?}",
                path
            )));
        }

        entry.unpack_in(output_dir)?;
    }
    Ok(())
}
