use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use anyhow::anyhow;
pub use dstack_core::InnerCryptoHelper;
use secp256k1::{ecdh::SharedSecret, SecretKey};

pub struct Crypto;

impl Crypto {
    pub fn new() -> Self {
        Self {}
    }
}

/// Cryptographic helpers for diffie-hellman secret sharing.
/// This should be moved to a default and either be derived or implemented in a wrapped object.
impl InnerCryptoHelper for Crypto {
    type Pubkey = secp256k1::PublicKey;
    type Secret = secp256k1::SecretKey;
    type EncryptedMessage = Vec<u8>;

    /// Generates a random keypair.
    fn get_keypair(&self) -> anyhow::Result<(Self::Pubkey, Self::Secret)> {
        let secret = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

        Ok((secret.public_key(&secp256k1::Secp256k1::new()), secret))
    }

    /// Decrypts [`message: Self::EncryptedMessage`]:
    /// 1. computes a shared secret (diffie hellman) between the provided public key (shared state pubkey) and secret key.
    /// 2. builds an aes encryption key from that shared secret ensuring that we're
    /// able to decrypt messages signed with the shared secret (note that
    /// shared(S_b, P_a) = shared(S_a, P_b) where S is secret and P is pubkey).
    /// 3. Decrypts the provided message using the provided nonce.
    /// 4. Builds [`Self::Secret`] from the decryption result.
    fn decrypt_secret<N: AsRef<[u8]>>(
        &self,
        nonce: N,
        message: Self::EncryptedMessage,
        pubkeys: Vec<Self::Pubkey>,
        secrets: Vec<Self::Secret>,
    ) -> anyhow::Result<Self::EncryptedMessage> {
        //let expected_shared_pubkey_bytes = pubkeys[0].;
        let chiper = {
            //let expected_shared_pubkey = secp256k1::PublicKey::from(*expected_shared_pubkey_bytes);
            let p2p_secret = SharedSecret::new(&pubkeys[0], &secrets[0]).secret_bytes();
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&p2p_secret);
            Aes256Gcm::new(key)
        };
        let decrypted = chiper
            .decrypt(GenericArray::from_slice(nonce.as_ref()), message.as_ref())
            .map_err(|e| anyhow!(e))?;

        Ok(decrypted)
    }

    /// Encrypts [`secret: Self::Secret`]:
    /// 1. computes a shared secret (diffie hellman) between the shared [`secret`]
    /// and the provided public key.
    /// 2. builds an aes encryption key from the shared secret ensuring that we're
    /// able to encrypt messages signed with the shared secret (note that here holds the condition
    /// shared(S_b, P_a) = shared(S_a, P_b) where S is secret and P is pubkey). Only the secret
    /// of the TDX-generated (this condition holds thanks to quote verification) [`pubkeys[0]`]
    /// will be able to compute a shared secret with the global shared pubkey.
    /// 3. We encrypt [`secret`] itself using the previously built key and return the result.
    fn encrypt_secret<N: AsRef<[u8]>>(
        &self,
        nonce: N,
        secret: Self::Secret,
        to_encrypt: Self::EncryptedMessage,
        pubkeys: Vec<Self::Pubkey>,
    ) -> anyhow::Result<Self::EncryptedMessage> {
        let chiper = {
            let p2p_secret = SharedSecret::new(&pubkeys[0], &secret).secret_bytes();
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&p2p_secret);
            Aes256Gcm::new(key)
        };
        let encrypted = chiper
            .encrypt(
                GenericArray::from_slice(nonce.as_ref()),
                to_encrypt.as_ref(),
            )
            .map_err(|e| anyhow!(e))?;
        Ok(encrypted)
    }
}
