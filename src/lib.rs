use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest}; // SHA-256 for hashing
use k256::ecdsa::{Signature, VerifyingKey};
use web_sys::console;
use k256::ecdsa::signature::Verifier;  // `Verifier` trait'ini ekledik

/// Enum representing possible ECDSA errors
/// Provides detailed feedback during signature verification failure.
#[derive(Debug, Serialize, Deserialize)]
pub enum ECDSAError {
    InvalidSignatureFormat,
    InvalidSignatureLength,
    InvalidSignatureRecovery,
    InvalidPublicKey,
}

impl std::fmt::Display for ECDSAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ECDSAError::InvalidSignatureFormat => write!(f, "Invalid signature format"),
            ECDSAError::InvalidSignatureLength => write!(f, "Invalid signature length"),
            ECDSAError::InvalidSignatureRecovery => write!(f, "Failed to recover public key"),
            ECDSAError::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

/// Struct for ECDSA signature verification using k256 crate.
#[wasm_bindgen]
pub struct ECDSAVerifier;

#[wasm_bindgen]
impl ECDSAVerifier {
    /// Initializes a new instance of ECDSAVerifier.
    #[wasm_bindgen(constructor)]
    pub fn new() -> ECDSAVerifier {
        ECDSAVerifier
    }

    /// Verifies a signature using a message, signature, and public key.
    /// 
    /// # Arguments:
    /// * `message` - The message that was signed.
    /// * `signature` - The digital signature to verify, provided as a hex string.
    /// * `public_key` - The signer's public key, provided as a hex string.
    /// 
    /// # Returns:
    /// * A boolean indicating whether the signature is valid or not.
    /// 
    /// # Errors:
    /// * Returns a descriptive error if the signature format is invalid, or the signature fails verification.
    pub fn verify_signature(
        &self,
        message: &str,
        signature: &str,
        public_key: &str,
    ) -> Result<bool, JsValue> {
        // Log the verification process
        console::log_1(&"Starting signature verification...".into());

        // Hash the input message using SHA-256
        let msg_hash = self.hash_message(message);

        // Decode the signature and public key from hex and check for length errors
        let signature_bytes = hex::decode(signature).map_err(|_| JsValue::from_str("Invalid signature format"))?;
        if signature_bytes.len() != 64 {
            return Err(JsValue::from_str("Signature length is invalid"));
        }

        let pubkey_bytes = hex::decode(public_key).map_err(|_| JsValue::from_str("Invalid public key format"))?;
        if pubkey_bytes.len() != 33 {
            return Err(JsValue::from_str("Public key length is invalid"));
        }

        // Convert the message hash, signature, and public key into appropriate types
        let sig = Signature::from_der(&signature_bytes).map_err(|_| JsValue::from_str("Invalid signature"))?;
        let pubkey = VerifyingKey::from_sec1_bytes(&pubkey_bytes).map_err(|_| JsValue::from_str("Invalid public key"))?;

        // Perform the signature verification using k256
        pubkey.verify(&msg_hash, &sig).map_err(|e| JsValue::from_str(&e.to_string()))?;

        console::log_1(&"Verification complete.".into());

        Ok(true)
    }

    /// Hashes the message using SHA-256.
    /// This function is used internally to prepare the message for signature verification.
    pub fn hash_message(&self, message: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize().to_vec() // Return the resulting hash
    }
}

/// Unit tests for ECDSAVerifier.
/// These tests cover valid signature verification, invalid signatures, and incorrect public keys.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_signature() {
        let verifier = ECDSAVerifier::new();
        let message = "Test message";
        let signature = "3045022100ebf...";  // Mock signature for testing
        let public_key = "03a0...";  // Mock public key for testing

        let result = verifier.verify_signature(message, signature, public_key);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_invalid_signature() {
        let verifier = ECDSAVerifier::new();
        let message = "Test message";
        let invalid_signature = "invalid_sig";
        let public_key = "03a0...";  // Mock public key for testing

        let result = verifier.verify_signature(message, invalid_signature, public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key() {
        let verifier = ECDSAVerifier::new();
        let message = "Test message";
        let signature = "3045022100ebf...";  // Mock signature for testing
        let invalid_public_key = "invalid_pubkey";

        let result = verifier.verify_signature(message, signature, invalid_public_key);
        assert!(result.is_err());
    }
}
