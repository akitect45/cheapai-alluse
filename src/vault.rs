//! Personal Authority Vault (`src/vault.rs`) — Hardware-Backed Encrypted Store.
//!
//! Provides canonical identity/card/login schemas, opaque-handle zero-leak autofill,
//! RFC 6238 TOTP generation, and credential redaction scrubbing using OS hardware protection
//! (Windows DPAPI) or cross-platform `AU01` AEAD encryption.

#[cfg(windows)]
use crate::win32_ffi::*;
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};
#[cfg(windows)]
use std::ptr;

const DPAPI_ENTROPY: &[u8] = b"alluse.native.arm64.vault.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultIdentity {
    pub id: String,
    pub label: String,
    pub first_name: String,
    pub last_name: String,
    pub full_name: String,
    pub email: String,
    pub phone: String,
    pub country: String,
    pub state_province: String,
    pub city: String,
    pub street_address: String,
    pub address_line2: String,
    pub postal_code: String,
    pub company: String,
    pub job_title: String,
    pub birth_date: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCard {
    pub id: String,
    pub label: String,
    pub cardholder_name: String,
    pub network: String,
    pub last_four: String,
    /// DPAPI-encrypted Base64 in storage; masked when serialized to UI/LLM summaries
    #[serde(default)]
    pub card_number_enc: String,
    pub exp_month: String,
    pub exp_year: String,
    /// DPAPI-encrypted Base64 in storage
    #[serde(default)]
    pub cvv_enc: String,
    pub billing_zip: String,
    pub billing_country: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCardDecrypted {
    pub id: String,
    pub label: String,
    pub cardholder_name: String,
    pub network: String,
    pub card_number: String,
    pub last_four: String,
    pub exp_month: String,
    pub exp_year: String,
    pub cvv: String,
    pub billing_zip: String,
    pub billing_country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLogin {
    pub id: String,
    pub service: String,
    pub url: String,
    pub username: String,
    pub email: String,
    #[serde(default)]
    pub password_enc: String,
    #[serde(default)]
    pub totp_secret_enc: String,
    pub has_password: bool,
    pub has_totp: bool,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLoginDecrypted {
    pub id: String,
    pub service: String,
    pub url: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub totp_secret: String,
    pub totp_code: Option<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSecret {
    pub id: String,
    pub key_name: String,
    pub category: String,
    #[serde(default)]
    pub value_enc: String,
    pub notes: String,
}

const PORTABLE_VAULT_MAGIC: &[u8; 4] = b"AU01";

static MACHINE_UUID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(mid) = std::fs::read_to_string(path) {
            let trimmed = mid.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains("\"IOPlatformUUID\"") {
                    if let Some((_, rhs)) = line.split_once('=') {
                        let uuid = rhs.trim().trim_matches(|c: char| c == '"' || c.is_whitespace());
                        if !uuid.is_empty() {
                            return uuid.to_string();
                        }
                    }
                }
            }
        }
        if let Ok(out) = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "kern.uuid"])
            .output()
        {
            let uuid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !uuid.is_empty() {
                return uuid;
            }
        }
    }
    String::new()
});

static VAULT_SEED_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, [u8; 32]>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
static VAULT_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn vault_key_backup_path(key_path: &std::path::Path) -> std::path::PathBuf {
    let mut os = key_path.as_os_str().to_os_string();
    os.push(".bak");
    std::path::PathBuf::from(os)
}

fn write_vault_seed_atomic(target: &std::path::Path, seed: &[u8; 32]) {
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let seq = VAULT_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp_os = target.as_os_str().to_os_string();
    tmp_os.push(format!(".{}.{}.tmp", std::process::id(), seq));
    let tmp_path = std::path::PathBuf::from(tmp_os);
    if std::fs::write(&tmp_path, seed).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        if std::fs::rename(&tmp_path, target).is_ok() {
            return;
        }
        let _ = std::fs::remove_file(&tmp_path);
    }
    let _ = std::fs::write(target, seed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o600));
    }
}

pub(crate) fn read_or_create_persistent_vault_key_seed_at(
    key_path: &std::path::Path,
) -> [u8; 32] {
    let mut guard = VAULT_SEED_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(cached) = guard.get(key_path).copied() {
        if std::fs::metadata(key_path)
            .map(|m| m.len() >= 32)
            .unwrap_or(false)
        {
            return cached;
        }
    }

    let bak_path = vault_key_backup_path(key_path);
    if let Ok(bytes) = std::fs::read(key_path) {
        if bytes.len() >= 32 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            if std::fs::metadata(&bak_path)
                .map(|m| m.len() < 32)
                .unwrap_or(true)
            {
                write_vault_seed_atomic(&bak_path, &seed);
            }
            guard.insert(key_path.to_path_buf(), seed);
            return seed;
        }
    }

    if let Ok(bak_bytes) = std::fs::read(&bak_path) {
        if bak_bytes.len() >= 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bak_bytes[..32]);
            write_vault_seed_atomic(key_path, &seed);
            guard.insert(key_path.to_path_buf(), seed);
            return seed;
        }
    }

    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed[16..32].copy_from_slice(uuid::Uuid::new_v4().as_bytes());

    write_vault_seed_atomic(key_path, &seed);
    write_vault_seed_atomic(&bak_path, &seed);

    if let Ok(bytes) = std::fs::read(key_path) {
        if bytes.len() >= 32 {
            let mut reread = [0u8; 32];
            reread.copy_from_slice(&bytes[..32]);
            guard.insert(key_path.to_path_buf(), reread);
            return reread;
        }
    }
    guard.insert(key_path.to_path_buf(), seed);
    seed
}

fn read_or_create_persistent_vault_key_seed() -> [u8; 32] {
    let key_path = crate::config::data_dir().join(".vault_master.key");
    read_or_create_persistent_vault_key_seed_at(&key_path)
}

fn derive_legacy_portable_vault_master_key() -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(DPAPI_ENTROPY).expect("HMAC accepts any key length");
    mac.update(b"alluse.portable.vault.v1|");
    if let Ok(mid) = std::fs::read_to_string("/etc/machine-id") {
        let trimmed = mid.trim();
        if !trimmed.is_empty() {
            mac.update(trimmed.as_bytes());
            mac.update(b"|");
        }
    }
    for var in ["COMPUTERNAME", "HOSTNAME", "USER", "USERNAME"] {
        if let Ok(val) = std::env::var(var) {
            let t = val.trim();
            if !t.is_empty() {
                mac.update(t.as_bytes());
                mac.update(b"|");
            }
        }
    }
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn derive_portable_vault_master_key() -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let seed = read_or_create_persistent_vault_key_seed();
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(DPAPI_ENTROPY).expect("HMAC accepts any key length");
    mac.update(b"alluse.portable.vault.v2|");
    mac.update(&seed);
    mac.update(b"|");
    let machine_uuid = MACHINE_UUID.as_str();
    if !machine_uuid.is_empty() {
        mac.update(machine_uuid.as_bytes());
        mac.update(b"|");
    }
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn portable_vault_keystream_xor(master_key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut out = Vec::with_capacity(data.len());
    for (block_idx, chunk) in data.chunks(32).enumerate() {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC accepts 32-byte key");
        mac.update(b"AU01-STREAM|");
        mac.update(nonce);
        mac.update(&(block_idx as u64).to_le_bytes());
        let stream_block = mac.finalize().into_bytes();
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ stream_block[i]);
        }
    }
    out
}

fn portable_vault_mac_tag(master_key: &[u8; 32], nonce: &[u8; 16], ciphertext: &[u8]) -> [u8; 16] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC accepts 32-byte key");
    mac.update(b"AU01-MAC|");
    mac.update(nonce);
    mac.update(ciphertext);
    let digest = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&digest[..16]);
    tag
}

fn encrypt_au01_with_key(plaintext: &[u8], master_key: &[u8; 32]) -> String {
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let ciphertext = portable_vault_keystream_xor(master_key, &nonce, plaintext);
    let tag = portable_vault_mac_tag(master_key, &nonce, &ciphertext);

    let mut blob = Vec::with_capacity(4 + 16 + ciphertext.len() + 16);
    blob.extend_from_slice(PORTABLE_VAULT_MAGIC);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob.extend_from_slice(&tag);
    base64::engine::general_purpose::STANDARD.encode(&blob)
}

fn decrypt_au01_with_key(raw: &[u8], master: &[u8; 32]) -> std::result::Result<Vec<u8>, String> {
    if raw.len() < 36 || &raw[..4] != PORTABLE_VAULT_MAGIC {
        return Err("CryptUnprotectData failed: invalid portable vault envelope".to_string());
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&raw[4..20]);
    let ciphertext = &raw[20..raw.len() - 16];
    let tag = &raw[raw.len() - 16..];

    let expected_tag = portable_vault_mac_tag(master, &nonce, ciphertext);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }
    if diff != 0 {
        return Err("CryptUnprotectData failed: authentication tag mismatch".to_string());
    }
    Ok(portable_vault_keystream_xor(master, &nonce, ciphertext))
}

fn portable_vault_encrypt(plaintext: &[u8]) -> String {
    let master_key = derive_portable_vault_master_key();
    encrypt_au01_with_key(plaintext, &master_key)
}

fn portable_vault_decrypt(raw: &[u8]) -> Result<String> {
    let primary_key = derive_portable_vault_master_key();
    if let Ok(plain_bytes) = decrypt_au01_with_key(raw, &primary_key) {
        return Ok(String::from_utf8_lossy(&plain_bytes).to_string());
    }
    let legacy_key = derive_legacy_portable_vault_master_key();
    let plain_bytes = decrypt_au01_with_key(raw, &legacy_key).map_err(|e| anyhow!(e))?;
    Ok(String::from_utf8_lossy(&plain_bytes).to_string())
}

/// Encrypts plaintext string using Windows DPAPI (`CryptProtectData`) on Windows or
/// portable HMAC-SHA256 authenticated encryption (`AU01` envelope) on macOS/Linux, returning Base64.
pub fn dpapi_encrypt(plaintext: &str) -> Result<String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    #[cfg(windows)]
    {
        let bytes = plaintext.as_bytes();
        let in_blob = DATA_BLOB {
            cbData: bytes.len() as DWORD,
            pbData: bytes.as_ptr() as *mut u8,
        };
        let entropy_blob = DATA_BLOB {
            cbData: DPAPI_ENTROPY.len() as DWORD,
            pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        unsafe {
            let ok = CryptProtectData(
                &in_blob,
                ptr::null(),
                &entropy_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok != 0 && !out_blob.pbData.is_null() {
                let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
                let b64 = base64::engine::general_purpose::STANDARD.encode(slice);
                let _ = LocalFree(out_blob.pbData as HANDLE);
                return Ok(b64);
            }
        }
    }
    Ok(portable_vault_encrypt(plaintext.as_bytes()))
}

fn strip_totp_outer_wrappers(raw: &str) -> &str {
    let mut s = raw.trim();
    for _ in 0..3 {
        let prev = s;
        if s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\''))
                || (s.starts_with('`') && s.ends_with('`'))
                || (s.starts_with('<') && s.ends_with('>'))
                || (s.starts_with('(') && s.ends_with(')'))
                || (s.starts_with('[') && s.ends_with(']')))
        {
            s = s[1..s.len() - 1].trim();
        }
        if s == prev {
            break;
        }
    }
    s
}

/// Decrypts a Base64-encoded Windows DPAPI or portable `AU01` vault blob back into UTF-8 plaintext.
pub fn dpapi_decrypt(cipher_b64: &str) -> Result<String> {
    let mut trimmed = strip_totp_outer_wrappers(cipher_b64);
    for _ in 0..3 {
        let mut stripped = false;
        for prefix in [
            "dpapi:", "dpapi=", "enc:", "enc=", "base64:", "base64=", "b64:", "b64=", "v1:",
            "vault:",
        ] {
            if let Some(head) = trimmed.get(..prefix.len())
                && head.eq_ignore_ascii_case(prefix)
            {
                trimmed = strip_totp_outer_wrappers(&trimmed[prefix.len()..]);
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    let compact: String = trimmed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{200B}' && *c != '\u{FEFF}')
        .collect();
    if compact.is_empty() {
        return Ok(String::new());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&compact))
        .map_err(|e| anyhow!("Invalid Base64 in DPAPI blob: {e}"))?;
    if raw.is_empty() {
        return Ok(String::new());
    }

    if raw.starts_with(PORTABLE_VAULT_MAGIC) {
        return portable_vault_decrypt(&raw);
    }

    #[cfg(windows)]
    {
        let in_blob = DATA_BLOB {
            cbData: raw.len() as DWORD,
            pbData: raw.as_ptr() as *mut u8,
        };
        let entropy_blob = DATA_BLOB {
            cbData: DPAPI_ENTROPY.len() as DWORD,
            pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        unsafe {
            let ok = CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                &entropy_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );
            if ok == 0 {
                bail!("CryptUnprotectData failed");
            }
            if out_blob.cbData == 0 || out_blob.pbData.is_null() {
                if !out_blob.pbData.is_null() {
                    let _ = LocalFree(out_blob.pbData as HANDLE);
                }
                return Ok(String::new());
            }
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let text = String::from_utf8_lossy(slice).to_string();
            let _ = LocalFree(out_blob.pbData as HANDLE);
            return Ok(text);
        }
    }

    #[cfg(not(windows))]
    bail!("CryptUnprotectData failed: unsupported vault ciphertext on non-Windows host")
}

fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| {
            !c.is_whitespace()
                && !matches!(
                    c,
                    '-' | '_'
                        | '.'
                        | '\u{200B}'
                        | '\u{FEFF}'
                        | '='
                        | '"'
                        | '\''
                        | '`'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '['
                        | ']'
                )
        })
        .map(|c| match c.to_ascii_uppercase() {
            '0' => 'O',
            '1' => 'L',
            '8' => 'B',
            other => other,
        })
        .collect();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::new();
    for ch in cleaned.chars() {
        let val: u32 = match ch {
            'A'..='Z' => (ch as u32) - ('A' as u32),
            '2'..='7' => (ch as u32) - ('2' as u32) + 26,
            _ => bail!("Invalid Base32 character '{ch}' in TOTP secret"),
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Pure Rust SHA-1 implementation for RFC 6238 / RFC 4226 standard TOTP codes.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha1_digest(key);
        k[..20].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5Cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha1_digest(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1_digest(&outer)
}

fn parse_totp_period_secs(raw: &str) -> Option<u64> {
    let mut s = strip_totp_outer_wrappers(raw);
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let mut scale = 1.0f64;
    for (suffix, mult) in [
        ("milliseconds", 0.001),
        ("millisecond", 0.001),
        ("msecs", 0.001),
        ("msec", 0.001),
        ("ms", 0.001),
        ("minutes", 60.0),
        ("minute", 60.0),
        ("mins", 60.0),
        ("min", 60.0),
        ("seconds", 1.0),
        ("second", 1.0),
        ("secs", 1.0),
        ("sec", 1.0),
        ("s", 1.0),
        ("m", 60.0),
    ] {
        if lower.ends_with(suffix) {
            if let Some(head) = s.get(..s.len() - suffix.len()) {
                s = head.trim();
                scale = mult;
            }
            break;
        }
    }
    let cleaned: String = s
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .chars()
        .filter(|&c| c != '_')
        .collect();
    let v = cleaned.trim().parse::<f64>().ok()?;
    if !v.is_finite() || v <= 0.0 {
        return None;
    }
    Some(((v * scale).round() as u64).clamp(1, 300))
}

fn extract_numeric_backup_code(raw: &str) -> Option<String> {
    let mut trimmed = strip_totp_outer_wrappers(raw);
    if let Some((lhs, rhs)) = trimmed.split_once(':').or_else(|| trimmed.split_once('='))
        && matches!(
            lhs.trim().to_ascii_lowercase().as_str(),
            "secret"
                | "totp_secret"
                | "totp_code"
                | "otp"
                | "code"
                | "totp"
                | "2fa"
                | "mfa"
                | "auth"
                | "seed"
                | "backup"
                | "pin"
                | "passcode"
                | "key"
                | "token"
        )
    {
        trimmed = strip_totp_outer_wrappers(rhs);
    }
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_digit() || c.is_ascii_whitespace() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    let digits_only: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    ((6..=8).contains(&digits_only.len())).then_some(digits_only)
}

/// Generates an RFC 6238 TOTP code (6..=8 digits, default 6; period 1..=300s, default 30s; SHA1, SHA256, or SHA512)
/// from a Base32 secret or `otpauth://` URI at the current system UNIX timestamp.
pub fn generate_totp_code(secret_or_uri: &str) -> Result<(String, u64)> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    generate_totp_code_at(secret_or_uri, now_secs)
}

/// Generates an RFC 6238 TOTP code at an explicit UNIX timestamp `now_secs`.
pub fn generate_totp_code_at(secret_or_uri: &str, now_secs: u64) -> Result<(String, u64)> {
    let mut raw_trimmed = strip_totp_outer_wrappers(secret_or_uri);
    if raw_trimmed.is_empty() {
        bail!("Empty TOTP secret");
    }
    let mut period: u64 = 30;
    let mut digits: usize = 6;
    let mut algo = "sha1";
    let mut json_extracted_secret: Option<String> = None;

    if raw_trimmed.starts_with('{')
        && raw_trimmed.ends_with('}')
        && let Ok(serde_json::Value::Object(map)) =
            serde_json::from_str::<serde_json::Value>(raw_trimmed)
    {
        for (k, v) in &map {
            let k_low = k.trim().to_ascii_lowercase();
            if matches!(
                k_low.as_str(),
                "secret"
                    | "totp_secret"
                    | "totp_code"
                    | "totp"
                    | "uri"
                    | "url"
                    | "key"
                    | "seed"
                    | "token"
                    | "otp"
                    | "code"
                    | "2fa"
                    | "mfa"
                    | "auth"
                    | "backup"
                    | "pin"
                    | "passcode"
            ) {
                if let Some(s) = v.as_str() {
                    let s_clean = strip_totp_outer_wrappers(s);
                    if !s_clean.is_empty() && (k_low == "secret" || json_extracted_secret.is_none())
                    {
                        json_extracted_secret = Some(s_clean.to_string());
                    }
                } else if let Some(n) = v.as_u64() {
                    if json_extracted_secret.is_none() {
                        json_extracted_secret = Some(n.to_string());
                    }
                }
            } else if matches!(k_low.as_str(), "period" | "step" | "interval") {
                if let Some(p) = v
                    .as_u64()
                    .map(|p| p.clamp(1, 300))
                    .or_else(|| v.as_str().and_then(parse_totp_period_secs))
                {
                    period = p;
                }
            } else if matches!(k_low.as_str(), "digits" | "length" | "len") {
                if let Some(d) = v.as_u64().map(|n| n as usize).or_else(|| {
                    v.as_str().and_then(|s| {
                        let d_clean: String = strip_totp_outer_wrappers(s)
                            .trim_end_matches(|c: char| c.is_ascii_alphabetic())
                            .chars()
                            .filter(|&c| c != '_')
                            .collect();
                        d_clean.trim().parse::<usize>().ok()
                    })
                }) {
                    digits = d.clamp(6, 8);
                }
            } else if matches!(k_low.as_str(), "algorithm" | "algo" | "hash")
                && let Some(s) = v.as_str()
            {
                let alg_val = strip_totp_outer_wrappers(s)
                    .to_ascii_lowercase()
                    .replace(['-', '_', ' '], "");
                if alg_val == "sha256" || alg_val == "hmacsha256" {
                    algo = "sha256";
                } else if alg_val == "sha512" || alg_val == "hmacsha512" {
                    algo = "sha512";
                }
            }
        }
        if let Some(ref inner) = json_extracted_secret {
            raw_trimmed = inner.as_str();
        }
    }

    if let Some(code) = extract_numeric_backup_code(raw_trimmed) {
        return Ok((code, period));
    }
    let pre_decoded_cow = if raw_trimmed
        .get(..16)
        .map(|p| p.eq_ignore_ascii_case("otpauth%3a%2f%2f"))
        .unwrap_or(false)
        || (!raw_trimmed.contains('?')
            && !raw_trimmed.contains('=')
            && (raw_trimmed.to_ascii_lowercase().contains("%3f")
                || raw_trimmed.to_ascii_lowercase().contains("%3d")))
    {
        urlencoding::decode(raw_trimmed)
            .map(|s| s.into_owned())
            .unwrap_or_else(|_| raw_trimmed.to_string())
    } else {
        raw_trimmed.to_string()
    };
    let trimmed = strip_totp_outer_wrappers(&pre_decoded_cow);

    let lower_trimmed = trimmed.to_ascii_lowercase();
    let has_kv_delimiters =
        (trimmed.contains('&') || trimmed.contains(';')) && trimmed.contains('=');
    let raw_secret = if lower_trimmed.starts_with("otpauth://")
        || lower_trimmed.contains("secret=")
        || trimmed.contains('?')
        || has_kv_delimiters
    {
        let (before_q, query) = if lower_trimmed.starts_with("otpauth://") {
            let no_frag = trimmed.split('#').next().unwrap_or(trimmed);
            if let Some((_b, q)) = no_frag.split_once('?') {
                ("", q)
            } else {
                let after_scheme = &no_frag["otpauth://".len()..];
                let tail = after_scheme
                    .split_once('/')
                    .map(|(_, path)| path.trim().trim_matches('/'))
                    .unwrap_or("")
                    .trim();
                let candidate = if !tail.is_empty()
                    && !tail.contains(':')
                    && !tail.contains('/')
                    && !tail.eq_ignore_ascii_case("totp")
                    && !tail.eq_ignore_ascii_case("hotp")
                {
                    tail
                } else {
                    ""
                };
                (candidate, "")
            }
        } else if let Some((b, q)) = trimmed.split_once('?') {
            (b.trim(), q.split('#').next().unwrap_or(q))
        } else {
            ("", trimmed.split('#').next().unwrap_or(trimmed))
        };
        let decoded_query_cow = if !query.contains('=')
            && (query.to_ascii_lowercase().contains("%3d")
                || query.to_ascii_lowercase().contains("%26"))
        {
            urlencoding::decode(query)
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| query.to_string())
        } else {
            query.to_string()
        };
        let norm_query = decoded_query_cow.replace("&amp;", "&").replace("&AMP;", "&");
        let mut found_secret: Option<String> = None;
        let mut bare_secret_candidate: Option<String> = None;
        for kv in norm_query.split(['&', ';']) {
            let kv_trimmed = strip_totp_outer_wrappers(kv);
            if kv_trimmed.is_empty() {
                continue;
            }
            if !kv_trimmed.trim_end_matches('=').contains('=') {
                if bare_secret_candidate.is_none() {
                    bare_secret_candidate = Some(kv_trimmed.to_string());
                }
                continue;
            }
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            let k_clean = k
                .trim()
                .strip_prefix("amp;")
                .or_else(|| k.trim().strip_prefix("AMP;"))
                .unwrap_or(k.trim())
                .trim();
            let k_low = k_clean.to_ascii_lowercase();
            let v_trimmed = strip_totp_outer_wrappers(v);
            if k_low == "secret"
                || (found_secret.is_none()
                    && matches!(
                        k_low.as_str(),
                        "totp"
                            | "totp_secret"
                            | "totp_code"
                            | "key"
                            | "seed"
                            | "token"
                            | "otp"
                            | "code"
                            | "2fa"
                            | "mfa"
                            | "auth"
                            | "backup"
                            | "pin"
                            | "passcode"
                    ))
            {
                if !v_trimmed.is_empty() {
                    found_secret = Some(v_trimmed.to_string());
                }
            } else if matches!(k_low.as_str(), "period" | "step" | "interval") {
                if let Some(p) = parse_totp_period_secs(v_trimmed) {
                    period = p;
                }
            } else if matches!(k_low.as_str(), "digits" | "length" | "len") {
                let d_clean: String = v_trimmed
                    .trim_end_matches(|c: char| c.is_ascii_alphabetic())
                    .chars()
                    .filter(|&c| c != '_')
                    .collect();
                if let Ok(d) = d_clean.trim().parse::<usize>() {
                    digits = d.clamp(6, 8);
                }
            } else if matches!(k_low.as_str(), "algorithm" | "algo" | "hash") {
                let alg_val = v_trimmed.to_ascii_lowercase().replace(['-', '_', ' '], "");
                if alg_val == "sha256" || alg_val == "hmacsha256" {
                    algo = "sha256";
                } else if alg_val == "sha512" || alg_val == "hmacsha512" {
                    algo = "sha512";
                }
            }
        }
        found_secret
            .or_else(|| {
                (!before_q.is_empty() && !before_q.trim_end_matches('=').contains('='))
                    .then(|| before_q.to_string())
            })
            .or(bare_secret_candidate)
            .ok_or_else(|| anyhow!("No secret= parameter in otpauth:// URI"))?
    } else {
        let base_part = trimmed.split('#').next().unwrap_or(trimmed).trim();
        let after_colon = if let Some((_, rhs)) = base_part.rsplit_once(':') {
            strip_totp_outer_wrappers(rhs)
        } else {
            base_part
        };
        if let Some((lhs, rhs)) = after_colon.split_once('=') {
            let lhs_low = lhs.trim().to_ascii_lowercase();
            let rhs_clean = strip_totp_outer_wrappers(rhs);
            if matches!(
                lhs_low.as_str(),
                "secret"
                    | "totp_secret"
                    | "totp_code"
                    | "totp"
                    | "key"
                    | "seed"
                    | "token"
                    | "otp"
                    | "code"
                    | "2fa"
                    | "mfa"
                    | "auth"
                    | "backup"
                    | "pin"
                    | "passcode"
            ) && !rhs_clean.is_empty()
            {
                rhs_clean.to_string()
            } else {
                after_colon.to_string()
            }
        } else {
            after_colon.to_string()
        }
    };

    let url_decoded = urlencoding::decode(&raw_secret)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| raw_secret.clone());
    if let Some(code) = extract_numeric_backup_code(&url_decoded) {
        return Ok((code, period));
    }
    let cleaned_secret = url_decoded
        .trim()
        .replace("%20", "")
        .replace("%3D", "")
        .replace("%3d", "")
        .replace("%2B", "")
        .replace("%2b", "")
        .replace("%2D", "")
        .replace("%2d", "")
        .replace("%5F", "")
        .replace("%5f", "")
        .replace('+', "");
    if let Some(code) = extract_numeric_backup_code(&cleaned_secret) {
        return Ok((code, period));
    }
    let key = decode_base32(&cleaned_secret)?;
    if key.is_empty() {
        bail!("Decoded TOTP secret key is empty");
    }
    let step = now_secs / period;
    let remaining = period - (now_secs % period);

    let msg = step.to_be_bytes();
    let hash_bytes: Vec<u8> = match algo {
        "sha256" => {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key size");
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        "sha512" => {
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(&key).expect("HMAC accepts any key size");
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        _ => hmac_sha1(&key, &msg).to_vec(),
    };
    let offset = (hash_bytes[hash_bytes.len() - 1] & 0x0F) as usize;
    let binary = ((hash_bytes[offset] as u32 & 0x7F) << 24)
        | ((hash_bytes[offset + 1] as u32) << 16)
        | ((hash_bytes[offset + 2] as u32) << 8)
        | (hash_bytes[offset + 3] as u32);
    let modulus = 10u32.pow(digits as u32);
    let code = binary % modulus;
    Ok((format!("{:0width$}", code, width = digits), remaining))
}

/// Computes a fast HMAC-SHA256 signature for internal IPC tokens.
pub fn compute_hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_totp_vectors_and_uri_options_are_deterministic() {
        // RFC 6238 ASCII secret "12345678901234567890" -> Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        let b32_sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code_59, rem_59) =
            generate_totp_code_at(&format!("{b32_sha1}?digits=8&period=30"), 59).unwrap();
        assert_eq!(code_59, "94287082");
        assert_eq!(rem_59, 1);

        let (code_1111111109, rem_1111111109) = generate_totp_code_at(
            &format!("otpauth://totp/Test:user?secret={b32_sha1}&digits=8&algorithm=SHA-1"),
            1_111_111_109,
        )
        .unwrap();
        assert_eq!(code_1111111109, "07081804");
        assert_eq!(rem_1111111109, 1);

        let (backup_code, backup_period) =
            generate_totp_code_at("secret=654321&period=60", 100).unwrap();
        assert_eq!(backup_code, "654321");
        assert_eq!(backup_period, 60);
    }

    #[test]
    fn totp_query_aliases_formatted_backup_codes_and_dpapi_roundtrip() {
        let b32_sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code_alias, rem_alias) =
            generate_totp_code_at(&format!("totp={b32_sha1}&step=30&len=8&algo=sha1"), 59).unwrap();
        assert_eq!(code_alias, "94287082");
        assert_eq!(rem_alias, 1);

        let (dash_backup, dash_rem) = generate_totp_code_at("987-654", 100).unwrap();
        assert_eq!(dash_backup, "987654");
        assert_eq!(dash_rem, 30);

        let (prefixed_backup, prefixed_rem) =
            generate_totp_code_at("backup: 123_456", 100).unwrap();
        assert_eq!(prefixed_backup, "123456");
        assert_eq!(prefixed_rem, 30);

        let (bare_padded_amp, bare_padded_rem) =
            generate_totp_code_at(&format!("{b32_sha1}==&digits=8&period=30"), 59).unwrap();
        assert_eq!(bare_padded_amp, "94287082");
        assert_eq!(bare_padded_rem, 1);

        let (bare_padded_q, _) =
            generate_totp_code_at(&format!("{b32_sha1}==?digits=8&period=30"), 59).unwrap();
        assert_eq!(bare_padded_q, "94287082");

        let (space_backup, space_rem) =
            generate_totp_code_at("key=\"1234 9876\"&interval=45", 100).unwrap();
        assert_eq!(space_backup, "12349876");
        assert_eq!(space_rem, 45);

        let (quoted_uri_code, quoted_uri_rem) = generate_totp_code_at(
            &format!("\"otpauth://totp/Test:user?secret={b32_sha1}&digits=8\""),
            59,
        )
        .unwrap();
        assert_eq!(quoted_uri_code, "94287082");
        assert_eq!(quoted_uri_rem, 1);

        let (backtick_uri_code, _) = generate_totp_code_at(
            &format!("`<otpauth://totp/Test:user?secret={b32_sha1}&digits=8&period=30000ms>`"),
            59,
        )
        .unwrap();
        assert_eq!(backtick_uri_code, "94287082");

        let (json_totp_code, json_totp_rem) = generate_totp_code_at(
            &format!(r#"{{"totp_secret": "{b32_sha1}", "step": "0.5m", "len": 8}}"#),
            59,
        )
        .unwrap();
        assert_eq!(json_totp_code, "94287082");
        assert_eq!(json_totp_rem, 1);

        let (unit_suffix_code, unit_suffix_rem) = generate_totp_code_at(
            &format!("secret={b32_sha1}&digits=8d&period=30s&algo=HMAC_SHA_1"),
            59,
        )
        .unwrap();
        assert_eq!(unit_suffix_code, "94287082");
        assert_eq!(unit_suffix_rem, 1);

        let (dot_pin_code, dot_pin_rem) =
            generate_totp_code_at("pin=123.456&period=1m", 100).unwrap();
        assert_eq!(dot_pin_code, "123456");
        assert_eq!(dot_pin_rem, 60);

        let (eq_backup_code, eq_backup_rem) = generate_totp_code_at("`2fa=654.321`", 100).unwrap();
        assert_eq!(eq_backup_code, "654321");
        assert_eq!(eq_backup_rem, 30);

        let (shorthand_uri_code, _) =
            generate_totp_code_at(&format!("otpauth://totp/{b32_sha1}"), 59).unwrap();
        assert_eq!(shorthand_uri_code, "287082");

        let (pct_query_code, _) = generate_totp_code_at(
            "otpauth://totp/ACME:alice?secret%3DJBSWY3DPEHPK3PXP%26digits%3D6",
            59,
        )
        .unwrap();
        let (plain_jbsw_code, _) = generate_totp_code_at("JBSWY3DPEHPK3PXP", 59).unwrap();
        assert_eq!(pct_query_code, plain_jbsw_code);

        let (dot_b32_code, _) = generate_totp_code_at("JBSW.Y3DP.EHPK.3PXP", 59).unwrap();
        assert_eq!(dot_b32_code, plain_jbsw_code);

        assert!(generate_totp_code_at("otpauth://totp/GitHub:alice?issuer=GitHub", 59).is_err());
        assert!(generate_totp_code_at("otpauth://totp/GitHub:alice", 59).is_err());

        assert_eq!(dpapi_encrypt("").unwrap(), "");
        assert_eq!(dpapi_decrypt("   ").unwrap(), "");
        let cipher = dpapi_encrypt("alluse-vault-secret-2026!").unwrap();
        assert!(!cipher.is_empty());
        assert_eq!(dpapi_decrypt(&cipher).unwrap(), "alluse-vault-secret-2026!");
        let wrapped_cipher = format!(
            "`dpapi:{}\r\n\u{00A0}\u{200B}  {}`",
            &cipher[..10],
            &cipher[10..]
        );
        assert_eq!(
            dpapi_decrypt(&wrapped_cipher).unwrap(),
            "alluse-vault-secret-2026!"
        );

        let mac = compute_hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            mac,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn portable_au01_envelope_roundtrip_and_legacy_key_fallback() {
        let plain = "portable-vault-secret-payload-2026";
        let au01_b64 = portable_vault_encrypt(plain.as_bytes());
        assert_eq!(dpapi_decrypt(&au01_b64).unwrap(), plain);

        let legacy_key = derive_legacy_portable_vault_master_key();
        let legacy_b64 = encrypt_au01_with_key(b"legacy-vault-secret-v1", &legacy_key);
        let legacy_raw = base64::engine::general_purpose::STANDARD
            .decode(&legacy_b64)
            .unwrap();
        assert_eq!(
            decrypt_au01_with_key(&legacy_raw, &legacy_key).unwrap(),
            b"legacy-vault-secret-v1"
        );
        assert_eq!(
            dpapi_decrypt(&legacy_b64).unwrap(),
            "legacy-vault-secret-v1"
        );

        let mut tampered = legacy_raw.clone();
        let last_idx = tampered.len() - 1;
        tampered[last_idx] ^= 0xFF;
        assert!(decrypt_au01_with_key(&tampered, &legacy_key).is_err());
    }

    #[test]
    fn vault_master_seed_is_concurrency_safe_and_recovers_from_truncated_key() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "alluse_vault_seed_test_{}_{}",
            std::process::id(),
            VAULT_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let key_path = std::sync::Arc::new(tmp_dir.join(".vault_master.key"));

        // 1. Concurrent callers on a fresh path must all observe the exact same 32-byte seed
        let mut handles = Vec::new();
        for _ in 0..8 {
            let kp = key_path.clone();
            handles.push(std::thread::spawn(move || {
                read_or_create_persistent_vault_key_seed_at(&kp)
            }));
        }
        let mut seeds = Vec::new();
        for h in handles {
            seeds.push(h.join().unwrap());
        }
        for s in &seeds[1..] {
            assert_eq!(s, &seeds[0], "concurrent vault seed initialization diverged");
        }

        // 2. Truncated .vault_master.key (< 32 bytes) recovers original seed from .bak
        std::fs::write(&*key_path, b"short").unwrap();
        let recovered = read_or_create_persistent_vault_key_seed_at(&key_path);
        assert_eq!(recovered, seeds[0]);
        assert_eq!(std::fs::read(&*key_path).unwrap().len(), 32);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
