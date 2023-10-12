// Copyright 2023 Antonio Estevez <aestgar62@gmail.com>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing
// permissions and limitations under the License.

//! # Crypto module.
//!
//! This module contains the cryptographic types and functions used by the
//! library.
//!

#![warn(missing_docs)]

#[cfg(feature = "ed25519")]
mod ed25519;

#[cfg(feature = "ed25519")]
pub use ed25519::Ed25519KeyPair;

#[cfg(feature = "secp256k1")]
mod secp256k1;

#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1KeyPair;

use crate::Error;

use memsecurity::EncryptedMem;

/// Base key pair.
///
/// This type contains the public key and some `EncryptedMem` object with the
/// secret key or none.
///
pub struct BaseKeyPair<K> {
    pub public: K,
    pub secret: Option<EncryptedMem>,
}

/// Key pair enumeration.
///
/// This type contains the key pair for the different algorithms.
///
pub enum KeyPair {
    /// Ed25519 key pair.
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519KeyPair),
    /// Secp256k1 key pair.
    #[cfg(feature = "secp256k1")]
    Secp256k1(Secp256k1KeyPair),
}

impl Signer for KeyPair {
    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The signature.
    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            #[cfg(feature = "ed25519")]
            KeyPair::Ed25519(key_pair) => key_pair.sign(message),
            #[cfg(feature = "secp256k1")]
            KeyPair::Secp256k1(key_pair) => key_pair.sign(message),
        }
    }
}

impl Verifier for KeyPair {
    /// Verify a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to verify.
    /// * `signature` - The signature.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(Error)` otherwise.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "ed25519")]
            KeyPair::Ed25519(key_pair) => key_pair.verify(message, signature),
            #[cfg(feature = "secp256k1")]
            KeyPair::Secp256k1(key_pair) => key_pair.verify(message, signature),
        }
    }
}

/// Key pair creator.
pub trait Creator {
    /// Create a new key pair from a secret.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key.
    ///
    /// # Returns
    ///
    /// A new key pair.
    fn from_secret(secret: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
    
    /// Create a new key pair from a public bytes.
    ///
    /// # Arguments
    /// 
    /// * `public` - The public key.
    /// 
    /// # Returns
    /// 
    /// A new key pair.
    fn from_public(public: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Key pair material.
pub trait KeyMaterial {
    /// Get the public key.
    ///
    /// # Returns
    ///
    /// Vec with the public key.
    fn to_vec(&self) -> Vec<u8>;
}

/// Key pair signer.
pub trait Signer {
    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign.
    ///
    /// # Returns
    ///
    /// The signature.
    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Key pair verifier.
pub trait Verifier {
    /// Verify a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to verify.
    /// * `signature` - The signature.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(Error)` otherwise.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_key_pair() {
        let key = "0123456789abcdef0123456789abcdef";
        let mut key_pair = KeyPair::Ed25519(Ed25519KeyPair::from_secret(key.as_bytes()).unwrap());
        let message = b"Hello, world!";
        let signature = key_pair.sign(message).unwrap();
        let result = key_pair.verify(message, &signature);
        assert!(result.is_ok());
        #[cfg(feature = "secp256k1")]
        {
            let mut key_pair =
                KeyPair::Secp256k1(Secp256k1KeyPair::from_secret(key.as_bytes()).unwrap());
            let signature = key_pair.sign(message).unwrap();
            let result = key_pair.verify(message, &signature);
            assert!(result.is_ok());
        }
    }
}
