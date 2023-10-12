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

//! # Identifiers module.
//! 

#![warn(missing_docs)]

mod derive;
mod digest;
mod key;
mod signature;

pub use derive::{Derivable, Derivator, DigestDerivator, KeyDerivator, SignatureDerivator};
pub use digest::DigestIdentifier;
pub use key::KeyIdentifier;
pub use signature::SignatureIdentifier;

use crate::Error;

use std::str::FromStr;

/// Enumeration of Identifier types
#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub(crate) enum Identifier {
    /// Digest identifier.
    Digest(DigestIdentifier),
    Key(KeyIdentifier),
    Signature(SignatureIdentifier),
}

impl Default for Identifier {
    fn default() -> Self {
        Identifier::Digest(DigestIdentifier::default())
    }
}

impl FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(id) = DigestIdentifier::from_str(s) {
            Ok(Identifier::Digest(id))
        } else if let Ok(id) = KeyIdentifier::from_str(s) {
            Ok(Identifier::Key(id))
        } else if let Ok(id) = SignatureIdentifier::from_str(s) {
            Ok(Identifier::Signature(id))
        } else {
            Err(Error::Decode("incorrect Identifier:".to_owned(), s.to_owned()))
        }
    }
}
