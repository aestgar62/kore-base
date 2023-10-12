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

//! # Ed25519 key pair module.
//!

#![warn(missing_docs)]

use super::{BaseKeyPair, Creator, Signer, Verifier, KeyMaterial};

use crate::Error;

use ed25519_dalek::{
    Signature, Signer as Ed25519Signer, SigningKey, Verifier as Ed25519Verifier, VerifyingKey,
};
use memsecurity::EncryptedMem;

/// Ed25519 key pair.
pub type Ed25519KeyPair = BaseKeyPair<VerifyingKey>;

impl Creator for Ed25519KeyPair {
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
        let sk = SigningKey::try_from(secret)
            .map_err(|_| Error::KeyPair("Ed25519".to_owned(), "geting SigningKey".to_owned()))?;
        let public_key = VerifyingKey::from(&sk);
        encrytion
            .encrypt(&sk.to_bytes())
            .map_err(|_| Error::KeyPair("Ed25519".to_owned(), "mem encryption".to_owned()))?; // grcov-excl-line
        Ok(Ed25519KeyPair {
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
        let public_key = VerifyingKey::try_from(public)
            .map_err(|_| Error::KeyPair("Ed25519".to_owned(), "geting VerifyingKey".to_owned()))?;
        Ok(Ed25519KeyPair {
            public: public_key,
            secret: None,
        })
    }
}

impl KeyMaterial for Ed25519KeyPair {
    fn to_vec(&self) -> Vec<u8> {
        self.public.to_bytes().to_vec()
    }
}

impl Signer for Ed25519KeyPair {
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
            "Ed25519".to_owned(),
            "secret not found".to_owned(),
        ))?;
        let sk = encr
            .decrypt()
            .map_err(|_| Error::KeyPair("Ed25519".to_owned(), "mem decryption".to_owned()))?; // grcov-excl-line

        let signing_key = SigningKey::try_from(sk.as_ref()).map_err(|_| {
            Error::KeyPair("Ed25519".to_owned(), "SigningKey from slice".to_owned())
        })?;
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

impl Verifier for Ed25519KeyPair {
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
        let sig = Signature::from_slice(signature)
            .map_err(|_| Error::KeyPair("Ed25519".to_owned(), "verify".to_owned()))?;
        self.public
            .verify(message, &sig)
            .map_err(|_| Error::KeyPair("Ed25519".to_owned(), "verify".to_owned()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sign_verify() {
        let secret = "0123456789abcdef0123456789abcdef";
        let message = b"Hello world!";
        let mut key_pair = Ed25519KeyPair::from_secret(secret.as_bytes()).unwrap();
        let signature = key_pair.sign(message).unwrap();
        let public_bytes = key_pair.to_vec();
        let kp = Ed25519KeyPair::from_public(&public_bytes).unwrap();
        assert!(kp.verify(message, &signature).is_ok());
        let key = "error";
        let key_pair_err = Ed25519KeyPair::from_secret(key.as_bytes());
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
