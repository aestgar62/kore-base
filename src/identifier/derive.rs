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

//! # Derive identifier module.
//! 

#![warn(missing_docs)]

use crate::Error;

use super::{SignatureIdentifier, KeyIdentifier};

#[cfg(feature = "blake3")]
use blake3;
#[cfg(feature = "sha2")]
use sha2::{Sha256, Sha512, Digest};
#[cfg(feature = "sha3")]
use sha3::{Sha3_256, Sha3_512};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use borsh::{BorshSerialize, BorshDeserialize};

use std::str::FromStr;

/// Derivable Identifiers
pub trait Derivable: FromStr<Err = Error> {
	
	/// Derivative value.
    fn derivative(&self) -> Vec<u8>;

    fn derivation_code(&self) -> String;

    fn to_str(&self) -> String {
        match self.derivative().len() {
            0 => "".to_string(),
            _ => [
                self.derivation_code(),
                general_purpose::URL_SAFE_NO_PAD.encode(self.derivative()),
            ]
            .join(""),
        }
    }
}

/// Derivator trait
pub trait Derivator {
    fn code_len(&self) -> usize;
    fn derivative_len(&self) -> usize;
    fn material_len(&self) -> usize {
        self.code_len() + self.derivative_len()
    }
    fn to_str(&self) -> String;
}

/// Enumeration with digest derivator types
#[derive(
    Debug,
    PartialEq,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
)]
pub enum DigestDerivator {
    /// Blake3 256
    #[cfg(feature = "blake3")]
    Blake3_256,
    /// Blake3 512
    #[cfg(feature = "blake3")]
    Blake3_512,
    /// SHA2 256
    #[cfg(feature = "sha2")]
    SHA2_256,
    /// SHA2 512
    #[cfg(feature = "sha2")]
    SHA2_512,
    /// SHA3 256
    #[cfg(feature = "sha3")]
    SHA3_256,
    /// SHA3 512
    #[cfg(feature = "sha3")]
    SHA3_512,
}

impl Default for DigestDerivator {
    fn default() -> Self {
        #[cfg(feature = "blake3")]
        return Self::Blake3_256;
        #[cfg(not(feature = "blake3"))]
        #[cfg(feature = "sha2")]
        return Self::SHA2_256;
        #[cfg(not(feature = "blake3"))]
        #[cfg(not(feature = "sha2"))]
        #[cfg(feature = "sha3")]
        return Self::SHA3_256;
    }
}

impl DigestDerivator {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3_256 => blake3_256_digest(data),
            #[cfg(feature = "blake3")]
            Self::Blake3_512 => blake3_512_digest(data),
            #[cfg(feature = "sha2")]
            Self::SHA2_256 => sha2_256_digest(data),
            #[cfg(feature = "sha2")]
            Self::SHA2_512 => sha2_512_digest(data),
            #[cfg(feature = "sha3")]
            Self::SHA3_256 => sha3_256_digest(data),
            #[cfg(feature = "sha3")]
            Self::SHA3_512 => sha3_512_digest(data),
        }
    }
}

impl Derivator for DigestDerivator {
    fn to_str(&self) -> String {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3_256 => "J",
            #[cfg(feature = "blake3")]
            Self::Blake3_512 => "0J",
            #[cfg(feature = "sha2")]
            Self::SHA2_256 => "L",
            #[cfg(feature = "sha2")]
            Self::SHA2_512 => "0L",
            #[cfg(feature = "sha3")]
            Self::SHA3_256 => "M",
            #[cfg(feature = "sha2")]
            Self::SHA3_512 => "0M",
        }
        .into()
    }

    fn code_len(&self) -> usize {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3_256 => 1,
            #[cfg(feature = "blake3")]
            Self::Blake3_512 => 2,
            #[cfg(feature = "sha2")]
            Self::SHA2_256 => 1,
            #[cfg(feature = "sha2")]
            Self::SHA2_512 => 2,
            #[cfg(feature = "sha3")]
            Self::SHA3_256 => 1,
            #[cfg(feature = "sha3")]
            Self::SHA3_512 => 2,
        }
    }

    fn derivative_len(&self) -> usize {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3_256 => 46,
            #[cfg(feature = "blake3")]
            Self::Blake3_512 => 83,
            #[cfg(feature = "sha2")]
            Self::SHA2_256 => 46,
            #[cfg(feature = "sha2")]
            Self::SHA2_512 => 83,
            #[cfg(feature = "sha3")]
            Self::SHA3_256 => 46,
            #[cfg(feature = "sha3")]
            Self::SHA3_512 => 83,
        }
    }
}

impl FromStr for DigestDerivator {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            #[cfg(feature = "blake3")]
            "J" => Ok(Self::Blake3_256),
            #[cfg(feature = "sha2")]
            "L" => Ok(Self::SHA2_256),
            #[cfg(feature = "sha3")]
            "M" => Ok(Self::SHA3_256),
            "0" => match &s[1..2] {
                #[cfg(feature = "blake3")]
                "J" => Ok(Self::Blake3_512),
                #[cfg(feature = "sha2")]
                "L" => Ok(Self::SHA2_512),
                #[cfg(feature = "sha3")]
                "M" => Ok(Self::SHA3_512),
                _ => Err(Error::Deserialize(format!("invalid derivator {}", s))),
            },
            _ => Err(Error::Deserialize(format!("invalid derivator {}", s))),
        }
    }
}

/// Performs blake3 256 digest.
#[cfg(feature = "blake3")]
fn blake3_256_digest(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}

/// Performs blake3 512 digest.
#[cfg(feature = "blake3")]
fn blake3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(input);
    h.finalize_xof().fill(&mut out);
    out.to_vec()
}

/// Performs sha2 256 digest.
#[cfg(feature = "sha2")]
fn sha2_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().to_vec()
}

/// Performs sha2 512 digest.
#[cfg(feature = "sha2")]
fn sha2_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update(input);
    h.finalize().to_vec()
}

/// Performs sha3 256 digest.
#[cfg(feature = "sha3")]
fn sha3_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(input);
    h.finalize().to_vec()
}

/// Performs sha3 512 digest.
#[cfg(feature = "sha3")]
fn sha3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_512::new();
    h.update(input);
    h.finalize().to_vec()
}


/// An enumeration of key derivator types.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    PartialOrd,
)]
pub enum KeyDerivator {
    /// The Ed25519 key derivator.
    Ed25519,
    /// The Secp256k1 key derivator.
    Secp256k1,
}

impl FromStr for KeyDerivator {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 0 {
            return Err(Error::Deserialize("empty derivator".to_owned()));
        }
        match &s[..1] {
            "E" => Ok(Self::Ed25519),
            "S" => Ok(Self::Secp256k1),
            _ => Err(Error::Deserialize("invalid derivator".to_owned())),
        }
    }
}

/// Enumeration with signature derivator types
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, BorshSerialize, BorshDeserialize, PartialOrd)]
pub enum SignatureDerivator {
    Ed25519Sha512,
    ECDSAsecp256k1,
}

impl SignatureDerivator {
    pub fn derive(&self, sign: &[u8]) -> SignatureIdentifier {
        SignatureIdentifier::new(*self, sign)
    }
}

impl Derivator for SignatureDerivator {
    fn code_len(&self) -> usize {
        match self {
            Self::Ed25519Sha512 | Self::ECDSAsecp256k1 => 2,
        }
    }

    fn derivative_len(&self) -> usize {
        match self {
            Self::Ed25519Sha512 | Self::ECDSAsecp256k1 => 86,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::Ed25519Sha512 => "SE",
            Self::ECDSAsecp256k1 => "SS",
        }
        .into()
    }
}

impl FromStr for SignatureDerivator {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &s[..1] {
            "S" => match &s[1..2] {
                "E" => Ok(Self::Ed25519Sha512),
                "S" => Ok(Self::ECDSAsecp256k1),
                _ => Err(Error::Decode("invalid derivator".to_owned(), s.to_owned())),
            },
            _ => Err(Error::Decode("invalid derivator".to_owned(), s.to_owned())),
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[cfg(feature = "blake3")]
    fn test_digest_blake3_256() {
        let derivator = DigestDerivator::Blake3_256;
        assert_eq!(derivator.code_len(), 1);
        assert_eq!(derivator.derivative_len(), 46);
        assert_eq!(derivator.material_len(), 47);
        assert_eq!(derivator.to_str(), "J");
        let data = "Hello World!";
        let digest = derivator.digest(data.as_bytes());
        let result = vec![92, 167, 129, 90, 220, 180, 132, 233, 161, 54, 193, 30, 254, 105, 193,
         213, 48, 23, 109, 84, 155, 93, 24, 208, 56, 235, 82, 128, 180, 179, 71, 12];
        assert_eq!(digest, result);
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn test_digest_blake3_512() {
        let derivator = DigestDerivator::Blake3_512;
        assert_eq!(derivator.code_len(), 2);
        assert_eq!(derivator.derivative_len(), 83);
        assert_eq!(derivator.material_len(), 85);
        assert_eq!(derivator.to_str(), "0J");
        let data = "Hello World!";
        let digest = derivator.digest(data.as_bytes());
        let result = vec![92, 167, 129, 90, 220, 180, 132, 233, 161, 54, 193, 30, 254, 105, 193,
         213, 48, 23, 109, 84, 155, 93, 24, 208, 56, 235, 82, 128, 180, 179, 71, 12, 221, 177, 116,
         107, 35, 71, 4, 151, 8, 51, 84, 183, 156, 64, 131, 31, 51, 228, 133, 151, 149, 30, 112, 72, 35,
         134, 121, 18, 3, 150, 98, 90];
        assert_eq!(digest, result);
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_digest_sha2_256() {
        let derivator = DigestDerivator::SHA2_256;
        assert_eq!(derivator.code_len(), 1);
        assert_eq!(derivator.derivative_len(), 46);
        assert_eq!(derivator.material_len(), 47);
        assert_eq!(derivator.to_str(), "L");
        let data = "Hello World!";
        let digest = derivator.digest(data.as_bytes());
        let result = [127, 131, 177, 101, 127, 241, 252, 83, 185, 45, 193, 129, 72, 161, 214, 93,
         252, 45, 75, 31, 163, 214, 119, 40, 74, 221, 210, 0, 18, 109, 144, 105];
        assert_eq!(digest, result);
    }

    #[test]
    #[cfg(feature = "sha2")]
    fn test_digest_sha2_512() {
        let derivator = DigestDerivator::SHA2_512;
        assert_eq!(derivator.code_len(), 2);
        assert_eq!(derivator.derivative_len(), 83);
        assert_eq!(derivator.material_len(), 85);
        assert_eq!(derivator.to_str(), "0L");
        let data = "Hello World!";
        let digest = derivator.digest(data.as_bytes());
        let result =[134, 24, 68, 214, 112, 78, 133, 115, 254, 195, 77, 150, 126, 32, 188, 254,
         243, 212, 36, 207, 72, 190, 4, 230, 220, 8, 242, 189, 88, 199, 41, 116, 51, 113, 1, 94, 173, 137,
         28, 195, 207, 28, 157, 52, 180, 146, 100, 181, 16, 117, 27, 31, 249, 229, 55, 147, 123, 196, 107,
         93, 111, 244, 236, 200];
        assert_eq!(digest, result); 
    }

    #[test]
    #[cfg(feature = "sha3")]
    fn test_digest_sha3_256() {
        let derivator = DigestDerivator::SHA3_256;
        assert_eq!(derivator.code_len(), 1);
        assert_eq!(derivator.derivative_len(), 46);
        assert_eq!(derivator.material_len(), 47);
        assert_eq!(derivator.to_str(), "M");
        let data = "Hello World!";
        let digest = derivator.digest(data.as_bytes());
        let result = vec![208, 228, 116, 134, 187, 244, 193, 106, 202, 194, 111, 139, 101, 53,
         146, 151, 60, 19, 98, 144, 159, 144, 38, 40, 119, 8, 159, 156, 138, 69, 54, 175];
        assert_eq!(digest, result);
    }

    #[test]
    #[cfg(feature = "sha3")]
    fn test_digest_sha3_512() {
        let derivator = DigestDerivator::SHA3_512;
        assert_eq!(derivator.code_len(), 2);
        assert_eq!(derivator.derivative_len(), 83);
        assert_eq!(derivator.material_len(), 85);
        assert_eq!(derivator.to_str(), "0M");
        let data = "Hello World!";
        let digest = derivator.digest(data.as_bytes());
        let result = vec![50, 64, 11, 94, 137, 130, 45, 226, 84, 232, 213, 217, 66, 82, 197, 43, 220,
         178, 122, 53, 98, 202, 89, 62, 152, 3, 100, 217, 132, 139, 128, 65, 185, 142, 171, 225, 108, 26, 103,
         151, 72, 73, 65, 210, 55, 104, 100, 161, 176, 226, 72, 176, 247, 175, 139, 21, 85, 167, 120, 195, 54, 165, 191, 72];
        assert_eq!(digest, result);
    }

}