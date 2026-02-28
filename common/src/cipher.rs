use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::time::{SystemTime, UNIX_EPOCH};

const KEY: [u8; 16] = [
    0x4A, 0x72, 0x61, 0x39, 0x55, 0x2B, 0x47, 0x31, 0x6E, 0x5A, 0x76, 0x48, 0x32, 0x30, 0x32, 0x36,
];

const NONCE_LEN: usize = 12; // GCM 需要 96-bit nonce

pub struct AesGcmCipher {
    cipher: LessSafeKey,
}

impl AesGcmCipher {
    pub fn new() -> AesGcmCipher {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &KEY).unwrap());
        Self { cipher }
    }

    pub fn encrypt(&self, payload: &str) -> String {
        let nonce_bytes = rand::random::<[u8; NONCE_LEN]>();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buffer = payload.as_bytes().to_vec();
        buffer.extend_from_slice(&[0u8; 16]);

        self.cipher
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
            .unwrap();

        // 输出格式为 nonce + ciphertext
        let mut output = nonce_bytes.to_vec();
        output.extend_from_slice(&buffer);

        general_purpose::STANDARD.encode(output)
    }

    pub fn check(&self, payload: &str) -> Result<()> {
        let decoded = general_purpose::STANDARD.decode(payload)?;

        if decoded.len() < NONCE_LEN + aead::AES_128_GCM.tag_len() {
            return Err(anyhow!("invalid length"));
        }

        let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into()?);
        let mut ciphertext = ciphertext.to_vec();

        let decrypted_data = self
            .cipher
            .open_in_place(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| anyhow!("decryption failed"))?;

        let plain = std::str::from_utf8(&decrypted_data[..decrypted_data.len() - 16])?;
        // 使用 & 分割字段后查找 time= 开头的字段
        let time_str_opt = plain.split('&').find_map(|part| part.strip_prefix("time="));
        let timestamp = time_str_opt
            .ok_or_else(|| anyhow!("time field not found"))?
            .parse::<u64>()?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if now.abs_diff(timestamp) <= 600 {
            Ok(())
        } else {
            Err(anyhow!("timestamp expired"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_check_valid_timestamp() {
        let cipher = AesGcmCipher::new();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let data = format!("time={}", ts);

        let encrypted = cipher.encrypt(&data);
        let result = cipher.check(&encrypted);

        assert!(result.is_ok(), "Decryption or timestamp check failed");
    }

    #[test]
    fn test_check_expired_timestamp() {
        let cipher = AesGcmCipher::new();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 601;
        let data = format!("time={}&user=test", ts);

        let encrypted = cipher.encrypt(&data);
        let result = cipher.check(&encrypted);

        assert!(result.is_err(), "Expected expiration check to fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timestamp expired")
        );
    }

    #[test]
    fn test_check_missing_time_field() {
        let cipher = AesGcmCipher::new();
        let data = "user=missingtimefield";

        let encrypted = cipher.encrypt(data);
        let result = cipher.check(&encrypted);

        assert!(
            result.is_err(),
            "Expected failure due to missing time field"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("time field not found")
        );
    }

    #[test]
    fn test_check_modified_data() {
        let cipher = AesGcmCipher::new();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let data = format!("time={}&user=test", ts);

        let encrypted = cipher.encrypt(&data);
        let mut encrypted_bytes = general_purpose::STANDARD.decode(&encrypted).unwrap();

        // 修改加密数据中的某一位
        encrypted_bytes[15] ^= 0xFF;

        let tampered = general_purpose::STANDARD.encode(&encrypted_bytes);
        let result = cipher.check(&tampered);

        assert!(
            result.is_err(),
            "Expected failure due to tampered ciphertext"
        );
    }
}
