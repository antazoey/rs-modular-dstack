// This should be moved outside of core and placed in the defaults.
// TODO: decide whether abstraction is needed for these.

use async_trait::async_trait;

#[async_trait]
pub trait InnerAttestationHelper {
    // TBD: are these the best constraints? Likely not.
    // TBD: make everything async?? Likely not
    type Appdata: Send + Sync;
    type Quote: Send + Sync;
    type VerificationResult;

    async fn get_quote(&self, appdata: Self::Appdata) -> anyhow::Result<Self::Quote>;

    async fn verify_quote(&self, quote: Self::Quote) -> anyhow::Result<Self::VerificationResult>;
}

pub trait InnerCryptoHelper {
    type Pubkey;
    type Secret;
    type EncryptedMessage;

    /// Getting a new (likely random) keypair
    fn get_keypair(&self) -> anyhow::Result<(Self::Pubkey, Self::Secret)>;

    fn encrypt_secret<N: AsRef<[u8]>>(
        &self,
        nonce: N,
        secret: Self::Secret,
        to_encrypt: Self::EncryptedMessage,
        pubkeys: Vec<Self::Pubkey>,
    ) -> anyhow::Result<Self::EncryptedMessage>;

    fn decrypt_secret<N: AsRef<[u8]>>(
        &self,
        nonce: N,
        message: Self::EncryptedMessage,
        pubkeys: Vec<Self::Pubkey>,
        secrets: Vec<Self::Secret>,
    ) -> anyhow::Result<Self::EncryptedMessage>;
}
