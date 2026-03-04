use crate::VncError;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};
use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum DH key length we accept from the server (bytes).
const MAX_KEY_LENGTH: usize = 1024;

/// Pack a credential string into a fixed-size buffer, null-terminated with random padding.
pub(crate) fn pack_credential_with_rng<R: Rng>(
    value: &str,
    buf_len: usize,
    rng: &mut R,
) -> Vec<u8> {
    let mut buf = vec![0u8; buf_len];
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(buf_len - 1); // leave room for null terminator
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    buf[copy_len] = 0; // null terminator
                       // fill remaining bytes with random padding
    for b in buf.iter_mut().skip(copy_len + 1) {
        *b = rng.gen();
    }
    buf
}

/// Derive AES-128 key from DH shared secret via MD5.
pub(crate) fn derive_aes_key(shared_secret: &BigUint) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(shared_secret.to_bytes_be());
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result);
    key
}

/// Encrypt 128-byte credentials block with AES-128-ECB.
pub(crate) fn encrypt_credentials(plaintext: &[u8; 128], aes_key: &[u8; 16]) -> [u8; 128] {
    let cipher = Aes128::new(aes_key.into());
    let mut ciphertext = [0u8; 128];
    ciphertext.copy_from_slice(plaintext);
    // AES-128-ECB: encrypt each 16-byte block
    for chunk in ciphertext.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    ciphertext
}

/// Zero-pad a BigUint to exactly `len` bytes (big-endian).
pub(crate) fn pad_to_length(value: &BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() >= len {
        bytes[bytes.len() - len..].to_vec()
    } else {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        padded
    }
}

/// Perform Apple Remote Desktop (ARD / security type 30) authentication.
///
/// Protocol steps:
/// 1. Read DH parameters from server: generator (u16), key_length (u16), prime, peer_public_key
/// 2. Generate client DH keypair
/// 3. Compute shared secret
/// 4. Derive AES-128 key via MD5(shared_secret)
/// 5. Pack username (64 bytes) + password (64 bytes) = 128 bytes
/// 6. Encrypt with AES-128-ECB
/// 7. Send: ciphertext (128 bytes) + client_public_key (key_length bytes)
/// 8. Read SecurityResult (u32): 0 = OK, non-zero = Failed
pub(crate) async fn authenticate_ard<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), VncError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Read DH parameters from server
    let generator = stream.read_u16().await?;
    let key_length = stream.read_u16().await? as usize;

    if key_length == 0 || key_length > MAX_KEY_LENGTH {
        return Err(VncError::General(format!(
            "ARD: invalid key_length {} (must be 1..={})",
            key_length, MAX_KEY_LENGTH
        )));
    }

    let mut prime_bytes = vec![0u8; key_length];
    stream.read_exact(&mut prime_bytes).await?;

    let mut peer_pub_bytes = vec![0u8; key_length];
    stream.read_exact(&mut peer_pub_bytes).await?;

    let prime = BigUint::from_bytes_be(&prime_bytes);
    let peer_public_key = BigUint::from_bytes_be(&peer_pub_bytes);
    let gen = BigUint::from(generator);

    // Steps 2-6 are computed synchronously before any further awaits,
    // so that `ThreadRng` (which is !Send+!Sync) is dropped before the next .await.
    let (ciphertext, client_public_key) = {
        let mut rng = rand::thread_rng();

        // Step 2: Generate client DH keypair
        let private_key = {
            let mut bytes = vec![0u8; key_length];
            rng.fill(&mut bytes[..]);
            let pk = BigUint::from_bytes_be(&bytes) % &prime;
            if pk.is_one() || pk == BigUint::ZERO {
                BigUint::from(2u32)
            } else {
                pk
            }
        };

        let client_public_key = gen.modpow(&private_key, &prime);

        // Step 3: Compute shared secret
        let shared_secret = peer_public_key.modpow(&private_key, &prime);

        // Step 4: Derive AES key
        let aes_key = derive_aes_key(&shared_secret);

        // Step 5: Pack credentials (username: 64 bytes, password: 64 bytes)
        let user_buf = pack_credential_with_rng(username, 64, &mut rng);
        let pass_buf = pack_credential_with_rng(password, 64, &mut rng);
        let mut credentials = [0u8; 128];
        credentials[..64].copy_from_slice(&user_buf);
        credentials[64..].copy_from_slice(&pass_buf);

        // Step 6: Encrypt
        let ciphertext = encrypt_credentials(&credentials, &aes_key);

        (ciphertext, client_public_key)
    }; // rng is dropped here, before any .await

    // Step 7: Send ciphertext + client public key
    stream.write_all(&ciphertext).await?;
    let pub_key_bytes = pad_to_length(&client_public_key, key_length);
    stream.write_all(&pub_key_bytes).await?;

    // Step 8: Read SecurityResult
    let result = stream.read_u32().await?;
    if result != 0 {
        return Err(VncError::WrongPassword);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_type_30_parsing() {
        use crate::client::auth::SecurityType;
        let st: SecurityType = 30u8.try_into().unwrap();
        assert_eq!(st, SecurityType::AppleRemoteDesktop);
        let byte: u8 = st.into();
        assert_eq!(byte, 30);
    }

    #[test]
    fn test_security_type_roundtrip() {
        use crate::client::auth::SecurityType;
        for val in [0, 1, 2, 5, 6, 16, 17, 18, 19, 20, 21, 22, 30] {
            let st: SecurityType = val.try_into().unwrap();
            let back: u8 = st.into();
            assert_eq!(back, val);
        }
    }

    #[test]
    fn test_invalid_security_type() {
        use crate::client::auth::SecurityType;
        let result: Result<SecurityType, _> = 99u8.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_pack_credential_username() {
        let packed = pack_credential_with_rng("admin", 64, &mut rand::thread_rng());
        assert_eq!(packed.len(), 64);
        assert_eq!(&packed[..5], b"admin");
        assert_eq!(packed[5], 0); // null terminator
    }

    #[test]
    fn test_pack_credential_password() {
        let packed = pack_credential_with_rng("secret123", 64, &mut rand::thread_rng());
        assert_eq!(packed.len(), 64);
        assert_eq!(&packed[..9], b"secret123");
        assert_eq!(packed[9], 0); // null terminator
    }

    #[test]
    fn test_pack_credential_empty() {
        let packed = pack_credential_with_rng("", 64, &mut rand::thread_rng());
        assert_eq!(packed.len(), 64);
        assert_eq!(packed[0], 0); // null terminator at start
    }

    #[test]
    fn test_pack_credential_max_length() {
        // If username is 63 chars, it fills 63 bytes + 1 null = 64 bytes exactly
        let long_name = "a".repeat(63);
        let packed = pack_credential_with_rng(&long_name, 64, &mut rand::thread_rng());
        assert_eq!(packed.len(), 64);
        assert_eq!(&packed[..63], long_name.as_bytes());
        assert_eq!(packed[63], 0);
    }

    #[test]
    fn test_pack_credential_truncates_at_buf_minus_one() {
        // If username is longer than buf_len - 1, it gets truncated
        let long_name = "a".repeat(100);
        let packed = pack_credential_with_rng(&long_name, 64, &mut rand::thread_rng());
        assert_eq!(packed.len(), 64);
        assert_eq!(&packed[..63], "a".repeat(63).as_bytes());
        assert_eq!(packed[63], 0);
    }

    #[test]
    fn test_derive_aes_key_known_input() {
        // MD5 of a known value should be deterministic
        let secret = BigUint::from(12345u32);
        let key = derive_aes_key(&secret);
        assert_eq!(key.len(), 16);

        // Verify it's the MD5 of the big-endian bytes of 12345
        let mut hasher = Md5::new();
        hasher.update(secret.to_bytes_be());
        let expected: [u8; 16] = hasher.finalize().into();
        assert_eq!(key, expected);
    }

    #[test]
    fn test_encrypt_credentials_produces_different_output() {
        let key = [0x42u8; 16];
        let mut plaintext = [0u8; 128];
        plaintext[..5].copy_from_slice(b"admin");
        plaintext[64..70].copy_from_slice(b"secret");

        let ciphertext = encrypt_credentials(&plaintext, &key);
        // Ciphertext should differ from plaintext
        assert_ne!(&ciphertext[..], &plaintext[..]);
        assert_eq!(ciphertext.len(), 128);
    }

    #[test]
    fn test_pad_to_length_shorter() {
        let val = BigUint::from(255u32); // 1 byte: 0xFF
        let padded = pad_to_length(&val, 4);
        assert_eq!(padded, vec![0, 0, 0, 0xFF]);
    }

    #[test]
    fn test_pad_to_length_exact() {
        let val = BigUint::from_bytes_be(&[1, 2, 3, 4]);
        let padded = pad_to_length(&val, 4);
        assert_eq!(padded, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_pad_to_length_longer() {
        // Value has more bytes than requested length - take last `len` bytes
        let val = BigUint::from_bytes_be(&[0, 0, 1, 2, 3, 4]);
        let padded = pad_to_length(&val, 4);
        assert_eq!(padded, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_ard_auth_failure() {
        let generator: u16 = 2;
        let key_length: u16 = 8;
        let prime_bytes = [0, 0, 0, 0, 0, 0, 0, 251u8];
        let peer_pub_bytes = [0, 0, 0, 0, 0, 0, 0, 5u8];
        let security_result: u32 = 1; // Failed

        let (mut client_end, mut server_end) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            server_end
                .write_all(&generator.to_be_bytes())
                .await
                .unwrap();
            server_end
                .write_all(&key_length.to_be_bytes())
                .await
                .unwrap();
            server_end.write_all(&prime_bytes).await.unwrap();
            server_end.write_all(&peer_pub_bytes).await.unwrap();

            // Read client response: 128 bytes ciphertext + key_length bytes public key
            let mut client_response = vec![0u8; 128 + key_length as usize];
            server_end.read_exact(&mut client_response).await.unwrap();

            // Send SecurityResult = 1 (Failed)
            server_end
                .write_all(&security_result.to_be_bytes())
                .await
                .unwrap();
        });

        let result = authenticate_ard(&mut client_end, "admin", "password").await;
        server_task.await.unwrap();

        assert!(result.is_err());
        assert!(
            matches!(result, Err(VncError::WrongPassword)),
            "Expected WrongPassword, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_ard_auth_success() {
        let generator: u16 = 2;
        let key_length: u16 = 8;
        let prime_bytes = [0, 0, 0, 0, 0, 0, 0, 251u8];
        let peer_pub_bytes = [0, 0, 0, 0, 0, 0, 0, 5u8];
        let security_result: u32 = 0; // OK

        let (mut client_end, mut server_end) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            server_end
                .write_all(&generator.to_be_bytes())
                .await
                .unwrap();
            server_end
                .write_all(&key_length.to_be_bytes())
                .await
                .unwrap();
            server_end.write_all(&prime_bytes).await.unwrap();
            server_end.write_all(&peer_pub_bytes).await.unwrap();

            let mut client_response = vec![0u8; 128 + key_length as usize];
            server_end.read_exact(&mut client_response).await.unwrap();

            server_end
                .write_all(&security_result.to_be_bytes())
                .await
                .unwrap();
        });

        let result = authenticate_ard(&mut client_end, "admin", "password").await;
        server_task.await.unwrap();

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
    }

    #[tokio::test]
    async fn test_ard_invalid_key_length_zero() {
        let generator: u16 = 2;
        let key_length: u16 = 0;

        let (mut client_end, mut server_end) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            server_end
                .write_all(&generator.to_be_bytes())
                .await
                .unwrap();
            server_end
                .write_all(&key_length.to_be_bytes())
                .await
                .unwrap();
        });

        let result = authenticate_ard(&mut client_end, "admin", "password").await;
        server_task.await.unwrap();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid key_length"),
            "Expected key_length error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_ard_invalid_key_length_too_large() {
        let generator: u16 = 2;
        let key_length: u16 = 2000; // > MAX_KEY_LENGTH (1024)

        let (mut client_end, mut server_end) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            server_end
                .write_all(&generator.to_be_bytes())
                .await
                .unwrap();
            server_end
                .write_all(&key_length.to_be_bytes())
                .await
                .unwrap();
        });

        let result = authenticate_ard(&mut client_end, "admin", "password").await;
        server_task.await.unwrap();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid key_length"),
            "Expected key_length error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_ard_credentials_packing_in_stream() {
        // Verify the full handshake sends 128 bytes ciphertext + key_length bytes public key
        let generator: u16 = 2;
        let key_length: u16 = 16;
        let prime_bytes = {
            let mut b = vec![0u8; 16];
            b[15] = 251; // prime = 251
            b
        };
        let peer_pub_bytes = {
            let mut b = vec![0u8; 16];
            b[15] = 5;
            b
        };

        let (mut client_end, mut server_end) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            server_end
                .write_all(&generator.to_be_bytes())
                .await
                .unwrap();
            server_end
                .write_all(&key_length.to_be_bytes())
                .await
                .unwrap();
            server_end.write_all(&prime_bytes).await.unwrap();
            server_end.write_all(&peer_pub_bytes).await.unwrap();

            // Read: 128 bytes ciphertext + 16 bytes public key
            let mut ciphertext = [0u8; 128];
            server_end.read_exact(&mut ciphertext).await.unwrap();

            let mut pub_key = [0u8; 16];
            server_end.read_exact(&mut pub_key).await.unwrap();

            // Public key should be non-zero (it's g^x mod p)
            assert!(
                pub_key.iter().any(|&b| b != 0),
                "Public key should not be all zeros"
            );

            // Send success
            server_end.write_all(&0u32.to_be_bytes()).await.unwrap();
        });

        let result = authenticate_ard(&mut client_end, "testuser", "testpass").await;
        server_task.await.unwrap();

        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
    }
}
