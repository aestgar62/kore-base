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

//! # Key identifier module.
//! 

#![warn(missing_docs)]

use super::{KeyDerivator, Derivable, Derivator};
use crate::Error;

use base64::{Engine as _, engine::general_purpose};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

/// Key based identifier
#[derive(Debug, Clone, Eq, Hash, BorshSerialize, BorshDeserialize, PartialOrd)]
pub struct KeyIdentifier {
    /// Key to derive.
    pub public_key: Vec<u8>,
    /// Key derivcator.
    pub derivator: KeyDerivator,
}

/// Partial equal for KeyIdentifier
impl PartialEq for KeyIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.derivator == other.derivator
    }
}

impl Display for KeyIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str(),)
    }
}

/// Derivable for KeyIdentifier
impl Derivable for KeyIdentifier {
    fn derivative(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn derivation_code(&self) -> String {
        self.derivator.to_str()
    }
}

impl Derivator for KeyDerivator {
    fn code_len(&self) -> usize {
        match self {
            Self::Ed25519 | Self::Secp256k1 => 1,
        }
    }

    fn derivative_len(&self) -> usize {
        match self {
            Self::Ed25519 => 43,
            Self::Secp256k1 => 87,
        }
    }

    fn to_str(&self) -> String {
        match self {
            Self::Ed25519 => "E",
            Self::Secp256k1 => "S",
        }
        .into()
    }
}


/// From string to KeyIdentifier
impl FromStr for KeyIdentifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = KeyDerivator::from_str(s)?;
        if s.len() == code.material_len() {
            let k_vec = general_purpose::URL_SAFE_NO_PAD
                .decode(&s[code.code_len()..code.material_len()])
                .map_err(|_| Error::Decode("base64".to_owned(), "invalid encode".to_owned()))?;
            Ok(Self {
                derivator: code,
                public_key: k_vec,
            })
        } else {
            Err(Error::Decode("incorrect Identifier Length".to_owned(), s.to_owned()))
        }
    }
}

/// Serde compatible Serialize
impl Serialize for KeyIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for KeyIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<KeyIdentifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::string::String as Deserialize>::deserialize(deserializer)?;

        KeyIdentifier::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::crypto::{Ed25519KeyPair, Creator, KeyMaterial};

    #[test]
    fn test_key_identifier() {
        let secret = "0123456789abcdef0123456789abcdef";
        let key_pair = Ed25519KeyPair::from_secret(secret.as_bytes()).unwrap();
        let key_identifier = KeyIdentifier {
            public_key: key_pair.to_vec(),
            derivator: KeyDerivator::Ed25519,
        };
        let key_identifier_str = key_identifier.to_str();
        let key_identifier2 = KeyIdentifier::from_str(&key_identifier_str).unwrap();
        assert_eq!(key_identifier, key_identifier2);

    }
}