// VNC-AUTH challenge/response encryption.
//
// VNC-AUTH (security type 2) authenticates by having the server send a
// 16-byte random challenge, the client encrypts it with single-DES in
// ECB mode keyed off the user's password (max 8 ASCII bytes, each byte
// bit-reversed per the original protocol quirk — see
// `client/auth.rs::AuthHelper::read`), and the server compares the
// result against its own copy.
//
// This module used to ship a 323-line hand-rolled DES implementation.
// It passed the FIPS 81 single-block test vector but mis-encrypted
// against libvncserver-based servers (e.g. gnome-remote-desktop in
// `password` mode) — the operator-visible symptom was the server
// returning `password check failed!` even with a correct 8-byte ASCII
// password that worked from every other VNC client. The bug was never
// pinned to a single line; instead we delegate every byte of crypto to
// RustCrypto's audited `des` crate. The hand-rolled IP/FP tables,
// S-boxes, Feistel function, and subkey scheduler are gone.
//
// Public surface stays the same so callers in `client/auth.rs`
// continue to work without touching the call sites.

// `decrypt` is part of the symmetric pair; the VNC client only ever
// calls `encrypt` (server compares), but mirroring the original
// module's API keeps downstream callers + future test plumbing
// straightforward.
#![allow(dead_code)]

use des::Des;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

pub type Key = [u8; 8];

/// Encrypt `message` under `key` with single-DES ECB. `message.len()`
/// must be a multiple of 8; for VNC-AUTH that's always 16 (the
/// challenge size).
pub fn encrypt(message: &[u8], key: &Key) -> Vec<u8> {
    let cipher = Des::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(message.len());
    for chunk in message.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

/// Decrypt `cipher` under `key` with single-DES ECB. Same length
/// requirement as [`encrypt`].
pub fn decrypt(cipher: &[u8], key: &Key) -> Vec<u8> {
    let des = Des::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(cipher.len());
    for chunk in cipher.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        des.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};

    /// FIPS 81 single-DES ECB known-answer vector. The hand-rolled
    /// implementation passed this test fine but still mis-encrypted
    /// against libvncserver-style servers — keeping the assertion
    /// here so any future swap of crypto crates surfaces a regression
    /// against this canonical reference.
    #[test]
    fn fips81_single_block_encrypt_decrypt_roundtrip() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let expected_cipher = [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];

        assert_eq!(encrypt(&plaintext, &key), expected_cipher.to_vec());
        assert_eq!(decrypt(&expected_cipher, &key), plaintext.to_vec());
    }

    /// Two-block (16 bytes — the VNC-AUTH challenge size) round-trip
    /// in ECB mode. Pins the loop boundary in case future refactors
    /// drop the per-chunk encryption.
    #[test]
    fn encrypts_two_blocks_ecb() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let plaintext = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let expected_cipher = [
            0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05, 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A,
            0xB4, 0x05,
        ];

        assert_eq!(encrypt(&plaintext, &key), expected_cipher.to_vec());
        assert_eq!(decrypt(&expected_cipher, &key), plaintext.to_vec());
    }
}
