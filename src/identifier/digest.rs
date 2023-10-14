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

//! # Digest identifier module.
//!

#![warn(missing_docs)]

use super::{Derivable, Derivator, DigestDerivator};

use crate::Error;

use base64::{engine::general_purpose, Engine as _};
use borsh::{BorshDeserialize, BorshSerialize};

use std::{
    default::Default,
    fmt::{Display, Formatter},
    str::FromStr,
};

/// Digest based identifier
#[derive(Debug, PartialEq, Clone, Eq, Hash, BorshSerialize, BorshDeserialize, PartialOrd)]
pub struct DigestIdentifier {
    /// Derivator.
    pub derivator: DigestDerivator,
    /// Digest.
    pub digest: Vec<u8>,
}

impl DigestIdentifier {
    /// Nes digest identifier.
    pub fn new(derivator: DigestDerivator, digest: &[u8]) -> Self {
        Self {
            derivator,
            digest: digest.to_vec(),
        }
    }
}

impl Default for DigestIdentifier {
    fn default() -> Self {
        DigestIdentifier {
            derivator: DigestDerivator::default(),
            digest: Vec::new(),
        }
    }
}

impl Derivable for DigestIdentifier {
    fn derivative(&self) -> Vec<u8> {
        self.digest.to_owned()
    }
    fn derivation_code(&self) -> String {
        self.derivator.to_str()
    }
}

impl Display for DigestIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str(),)
    }
}

/// From string to KeyIdentifier
impl FromStr for DigestIdentifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(DigestIdentifier::default());
        }
        let code = DigestDerivator::from_str(s)?;
        if s.len() == code.material_len() {
            Ok(Self::new(
                code,
                &general_purpose::URL_SAFE_NO_PAD
                    .decode(&s[code.code_len()..code.material_len()])
                    .map_err(|_| Error::Decode("base64".to_owned(), "invalid encode".to_owned()))?,
            ))
        } else {
            Err(Error::Decode(
                "DigestIdentifier".to_owned(),
                "invalid length".to_owned(),
            ))
        }
    }
}
