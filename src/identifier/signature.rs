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

//! # Signature identifier module.
//! 

#![warn(missing_docs)]

use super::{Derivator, Derivable, SignatureDerivator};

use crate::Error;

use base64::{Engine as _, engine::general_purpose};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::{
    fmt::{Formatter, Display},
    str::FromStr,
};

/// Signature based identifier
#[derive(Debug, PartialEq, Clone, Eq, Hash, BorshSerialize, BorshDeserialize, PartialOrd)]
pub struct SignatureIdentifier {
    pub derivator: SignatureDerivator,
    pub signature: Vec<u8>,
}

impl SignatureIdentifier {
    pub fn new(derivator: SignatureDerivator, signature: &[u8]) -> Self {
        Self {
            derivator,
            signature: signature.to_vec(),
        }
    }
}

impl Derivable for SignatureIdentifier {
    fn derivative(&self) -> Vec<u8> {
        self.signature.to_owned()
    }
    fn derivation_code(&self) -> String {
        self.derivator.to_str()
    }
}

impl Display for SignatureIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str(),)
    }
}

impl FromStr for SignatureIdentifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = SignatureDerivator::from_str(s)?;
        if s.len() == code.material_len() {
            Ok(Self::new(
                code,
                &general_purpose::URL_SAFE_NO_PAD.decode(&s[code.code_len()..code.material_len()])
                    .map_err(|_| Error::Decode("incorrect Signature:".to_owned(), s.to_owned()))?,
            ))
        } else {
            Err(Error::Decode("incorrect Prefix Length:".to_owned(), s.len().to_string()))
        }
    }
}

impl Serialize for SignatureIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

impl<'de> Deserialize<'de> for SignatureIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<SignatureIdentifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::string::String as Deserialize>::deserialize(deserializer)?;

        SignatureIdentifier::from_str(&s).map_err(serde::de::Error::custom)
    }
}
