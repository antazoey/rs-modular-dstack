//! Note, defaults to tsm only attestation through

use async_trait::async_trait;
pub use dstack_core::InnerAttestationHelper;
use sha2::{Digest, Sha256};

pub struct Attestation {}

impl Attestation {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(feature="tsm_only")]
mod tsm_att {
    use tsm_client::{make_client, report};

    use super::*;

    #[async_trait]
    impl InnerAttestationHelper for Attestation {
        type Appdata = Vec<u8>;
        type Quote = String;
        type VerificationResult = dcap_qvl::verify::VerifiedReport;

        async fn get_quote(&self, appdata: Self::Appdata) -> anyhow::Result<Self::Quote> {
            let preimage = format!("register{}", hex::encode(appdata));
            let mut hasher = Sha256::new();
            hasher.update(preimage);
            let hashed: Vec<u8> = hasher.finalize().to_vec();
            let mut padded_report_data = [0_u8; 64];
            padded_report_data[..hashed.len()].copy_from_slice(&hashed);

            let quote = {
                let client = make_client()?;
                let request = report::Request {
                    in_blob: padded_report_data.to_vec(),
                    privilege: None,
                    get_aux_blob: false
                };
                let mut report = report::create(client, request)?;
                report.get()?.out_blob
            };

            let hex_quote = hex::encode(quote);            
            Ok(hex_quote)
        }

        async fn verify_quote(&self, quote: Self::Quote) -> anyhow::Result<Self::VerificationResult> {
            let quote = hex::decode(quote)?;
            
            // we're just relying on intel's API. We can change whenever we want.
            let client = dcap_qvl::collateral::CollateralClient::with_default_http(
                dcap_qvl::collateral::INTEL_PCS_URL,
            )?;
            let collateral = client.fetch(&quote).await?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let tcb = dcap_qvl::verify::verify(&quote, &collateral, now)?;

            Ok(tcb)
        }
    }
}

#[cfg(feature="full_c_driver")]
mod full_driver {
    use super::*;

    #[async_trait]
    impl InnerAttestationHelper for Attestation {
        type Appdata = Vec<u8>;
        type Quote = String;
        type VerificationResult = dcap_qvl::verify::VerifiedReport;

        async fn get_quote(&self, appdata: Self::Appdata) -> anyhow::Result<Self::Quote> {
            let preimage = format!("register{}", hex::encode(appdata));
            let mut hasher = Sha256::new();
            hasher.update(preimage);
            let hashed: Vec<u8> = hasher.finalize().to_vec();
            let mut padded_report_data = [0_u8; 64];
            padded_report_data[..hashed.len()].copy_from_slice(&hashed);

            let (_, quote) = tdx_attest::get_quote(&padded_report_data, None)?;
            let hex_quote = hex::encode(quote);
            println!("Hex Output: {}", hex_quote);
            
            Ok(hex_quote)
        }

        async fn verify_quote(&self, quote: Self::Quote) -> anyhow::Result<Self::VerificationResult> {
            let quote = hex::decode(quote)?;
            
            // we're just relying on intel's API. We can change whenever we want.
            let client = dcap_qvl::collateral::CollateralClient::with_default_http(
                dcap_qvl::collateral::INTEL_PCS_URL,
            )?;
            let collateral = client.fetch(&quote).await?;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let tcb = dcap_qvl::verify::verify(&quote, &collateral, now)?;

            Ok(tcb)
        }
    }
}
