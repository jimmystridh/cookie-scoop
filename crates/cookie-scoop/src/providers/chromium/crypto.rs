use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    InvalidCiphertext,
    HostBinding,
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCiphertext => "Invalid Chromium cookie ciphertext",
            Self::HostBinding => "Chromium cookie host binding verification failed",
        })
    }
}

impl std::error::Error for DecryptError {}

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub fn derive_aes128_cbc_key(password: &str, iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; 16];
    pbkdf2_hmac::<Sha1>(password.as_bytes(), b"saltysalt", iterations, &mut key);
    key
}

pub fn decrypt_chromium_aes128_cbc(
    encrypted_value: &[u8],
    key_candidates: &[Vec<u8>],
    expected_host: Option<&str>,
    treat_unknown_prefix_as_plaintext: bool,
) -> Result<String, DecryptError> {
    let prefix = encrypted_value
        .get(..3)
        .ok_or(DecryptError::InvalidCiphertext)?;
    if !is_version_prefix(prefix) {
        if treat_unknown_prefix_as_plaintext {
            return decode_cookie_value_bytes(encrypted_value, expected_host);
        }
        return Err(DecryptError::InvalidCiphertext);
    }

    let ciphertext = &encrypted_value[3..];
    let mut failure = DecryptError::InvalidCiphertext;
    for key in key_candidates {
        let iv = [0x20; 16];
        let mut buffer = ciphertext.to_vec();
        let Some(plaintext) = Aes128CbcDec::new_from_slices(key, &iv)
            .ok()
            .and_then(|decoder| decoder.decrypt_padded_mut::<Pkcs7>(&mut buffer).ok())
        else {
            continue;
        };
        match decode_cookie_value_bytes(plaintext, expected_host) {
            Ok(value) => return Ok(value),
            Err(DecryptError::HostBinding) => failure = DecryptError::HostBinding,
            Err(DecryptError::InvalidCiphertext) => {}
        }
    }
    Err(failure)
}

pub fn decrypt_chromium_aes256_gcm(
    encrypted_value: &[u8],
    key: &[u8],
    expected_host: Option<&str>,
) -> Result<String, DecryptError> {
    let prefix = encrypted_value
        .get(..3)
        .ok_or(DecryptError::InvalidCiphertext)?;
    if !is_version_prefix(prefix) {
        return Err(DecryptError::InvalidCiphertext);
    }
    let payload = &encrypted_value[3..];
    let nonce = payload.get(..12).ok_or(DecryptError::InvalidCiphertext)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| DecryptError::InvalidCiphertext)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), &payload[12..])
        .map_err(|_| DecryptError::InvalidCiphertext)?;
    decode_cookie_value_bytes(&plaintext, expected_host)
}

fn is_version_prefix(prefix: &[u8]) -> bool {
    prefix[0] == b'v' && prefix[1].is_ascii_digit() && prefix[2].is_ascii_digit()
}

fn decode_cookie_value_bytes(
    value: &[u8],
    expected_host: Option<&str>,
) -> Result<String, DecryptError> {
    let bytes = if let Some(host) = expected_host {
        let digest = Sha256::digest(host.as_bytes());
        value
            .strip_prefix(&digest[..])
            .ok_or(DecryptError::HostBinding)?
    } else {
        value
    };
    let decoded = std::str::from_utf8(bytes).map_err(|_| DecryptError::InvalidCiphertext)?;
    Ok(strip_leading_control_chars(decoded))
}

fn strip_leading_control_chars(value: &str) -> String {
    let trimmed = value.trim_start_matches(|c: char| (c as u32) < 0x20);
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let key = derive_aes128_cbc_key("peanuts", 1);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_derive_key_macos_iterations() {
        let key = derive_aes128_cbc_key("test_password", 1003);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

        let password = "test_password";
        let key = derive_aes128_cbc_key(password, 1003);
        let iv = [0x20u8; 16];
        let plaintext = b"hello_cookie_value";

        let encryptor = Aes128CbcEnc::new_from_slices(&key, &iv).unwrap();
        let mut buf = vec![0u8; plaintext.len() + 16]; // room for padding
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ciphertext = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .to_vec();

        // Prepend v10 prefix
        let mut encrypted = b"v10".to_vec();
        encrypted.extend_from_slice(&ciphertext);

        let result = decrypt_chromium_aes128_cbc(&encrypted, &[key], None, false);
        assert_eq!(result, Ok("hello_cookie_value".to_string()));
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key_bytes = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"gcm_cookie_value";

        let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext_with_tag = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Layout: v10 + nonce(12) + ciphertext + tag(16)
        let mut encrypted = b"v10".to_vec();
        encrypted.extend_from_slice(&nonce_bytes);
        // ciphertext_with_tag already has tag appended
        encrypted.extend_from_slice(&ciphertext_with_tag);

        let result = decrypt_chromium_aes256_gcm(&encrypted, &key_bytes, None);
        assert_eq!(result, Ok("gcm_cookie_value".to_string()));
    }

    #[test]
    fn test_unknown_prefix_as_plaintext() {
        let data = b"plain_cookie_value";
        let result = decrypt_chromium_aes128_cbc(data, &[], None, true);
        assert_eq!(result, Ok("plain_cookie_value".to_string()));
    }

    #[test]
    fn test_unknown_prefix_strict() {
        let data = b"plain_cookie_value";
        let result = decrypt_chromium_aes128_cbc(data, &[], None, false);
        assert_eq!(result, Err(DecryptError::InvalidCiphertext));
    }

    #[test]
    fn verifies_hash_prefix_against_the_raw_host_key() {
        let mut data = Sha256::digest(b".example.test").to_vec();
        data.extend_from_slice(b"actual_value");
        assert_eq!(
            decode_cookie_value_bytes(&data, Some(".example.test")),
            Ok("actual_value".to_owned())
        );
        assert_eq!(
            decode_cookie_value_bytes(&data, Some("example.test")),
            Err(DecryptError::HostBinding)
        );
        assert_eq!(
            decode_cookie_value_bytes(&data[..20], Some(".example.test")),
            Err(DecryptError::HostBinding)
        );
    }
}
