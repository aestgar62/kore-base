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

//! # Secp256k1 key pair module.
//!

#![warn(missing_docs)]

use super::{BaseKeyPair, Creator, KeyMaterial, Signer, Verifier};

use crate::Error;

use memsecurity::EncryptedMem;

use k256::ecdsa::{
    signature::{Signer as Secp256k1Signer, Verifier as Secp256k1Verifier},
    Signature, SigningKey, VerifyingKey,
};

/// Secp256k1 key pair.
pub type Secp256k1KeyPair = BaseKeyPair<VerifyingKey>;

impl Creator for Secp256k1KeyPair {
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
        Self: Sized,
    {
        let mut encrytion = EncryptedMem::new();
        let sk = SigningKey::from_slice(secret)
            .map_err(|_| Error::KeyPair("Secp256k1".to_owned(), "geting SecretKey".to_owned()))?;
        let public_key = VerifyingKey::from(&sk);
        encrytion
            .encrypt(&sk.to_bytes())
            .map_err(|_| Error::KeyPair("Secp256k1".to_owned(), "mem encryption".to_owned()))?; // grcov-excl-line

        Ok(Secp256k1KeyPair {
            public: public_key,
            secret: Some(encrytion),
        })
    }

    /// Create a new key pair from a public key.
    ///
    /// # Arguments
    ///
    /// * `public` - The public key.
    ///
    /// # Returns
    ///
    /// A new key pair.
    ///
    fn from_public(public: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let public_key = VerifyingKey::from_sec1_bytes(public).map_err(|_| {
            Error::KeyPair("Secp256k1".to_owned(), "geting VerifyingKey".to_owned())
        })?;
        Ok(Secp256k1KeyPair {
            public: public_key,
            secret: None,
        })
    }
}

impl KeyMaterial for Secp256k1KeyPair {
    fn to_vec(&self) -> Vec<u8> {
        self.public.to_sec1_bytes().to_vec()
    }
}
impl Signer for Secp256k1KeyPair {
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
        let encr = self.secret.as_ref().ok_or(Error::KeyPair(
            "Secp256k1".to_owned(),
            "secret not found".to_owned(),
        ))?;
        let sk = encr
            .decrypt()
            .map_err(|_| Error::KeyPair("Secp256k1".to_owned(), "mem decryption".to_owned()))?; // grcov-excl-line
        let signing_key = SigningKey::try_from(sk.as_ref()).map_err(|_| {
            Error::KeyPair("Secp256k1".to_owned(), "SigningKey from slice".to_owned())
        })?;
        let signature: Signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

impl Verifier for Secp256k1KeyPair {
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
        let signature = Signature::try_from(signature).map_err(|_| {
            Error::KeyPair("Secp256k1".to_owned(), "Signature from slice".to_owned())
        })?;
        self.public
            .verify(message, &signature)
            .map_err(|_| Error::KeyPair("Secp256k1".to_owned(), "verifying".to_owned()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sign_verify() {
        let key = "0123456789abcdef0123456789abcdef";
        let mut key_pair = Secp256k1KeyPair::from_secret(key.as_bytes()).unwrap();
        let message = b"Hello, world!";
        let signature = key_pair.sign(message).unwrap();
        let public = key_pair.to_vec();
        let kp = Secp256k1KeyPair::from_public(&public).unwrap();
        let result = kp.verify(message, &signature);
        assert!(result.is_ok());
        let key = "error";
        let key_pair_err = Secp256k1KeyPair::from_secret(key.as_bytes());
        assert!(key_pair_err.is_err());
        let mut encrytion = EncryptedMem::new();
        encrytion.encrypt(b"error").unwrap();
        key_pair.secret = Some(encrytion);
        let signature = key_pair.sign(message);
        assert!(signature.is_err());
        key_pair.secret = None;
        let signature = key_pair.sign(message);
        assert!(signature.is_err());
    }
}
