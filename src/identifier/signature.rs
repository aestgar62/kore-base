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

use super::{Derivable, Derivator, SignatureDerivator};

use crate::Error;

use base64::{engine::general_purpose, Engine as _};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::{
    fmt::{Display, Formatter},
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
                &general_purpose::URL_SAFE_NO_PAD
                    .decode(&s[code.code_len()..code.material_len()])
                    .map_err(|_| Error::Decode("incorrect Signature:".to_owned(), s.to_owned()))?,
            ))
        } else {
            Err(Error::Decode(
                "incorrect Prefix Length:".to_owned(),
                s.len().to_string(),
            ))
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

#[cfg(test)]
mod tests {

    use super::*;

    use crate::crypto::{Creator, Ed25519KeyPair, Secp256k1KeyPair, Verifier, Signer};

    #[test]
    fn test_signature() {
        let secret = "0123456789abcdef0123456789abcdef";
        let message = "test message";
        let mut kp = Ed25519KeyPair::from_secret(secret.as_bytes()).unwrap();
        let sig = kp.sign(message.as_bytes()).unwrap();
        let id = SignatureIdentifier::new(SignatureDerivator::Ed25519Sha512, &sig);
        assert_eq!(id.derivator, SignatureDerivator::Ed25519Sha512);
        let sig_str = "SERwVEryPQBCsphRO2ybI7lfO7RvPt_jnbHlRqI0EsRGwesLVM30kwto4Xr4Zeo3Q4fv14B8BDkOek2aHWhj7oDg";
        assert_eq!(id.to_str(), sig_str);
        let id2 = SignatureIdentifier::from_str(sig_str).unwrap();
        assert_eq!(id, id2);
        let result = kp.verify(message.as_bytes(), id2.derivative().as_slice());
        assert!(result.is_ok());
        let mut kp = Secp256k1KeyPair::from_secret(secret.as_bytes()).unwrap();
        let sig = kp.sign(message.as_bytes()).unwrap();
        let id = SignatureIdentifier::new(SignatureDerivator::ECDSAsecp256k1, &sig);
        assert_eq!(id.derivator, SignatureDerivator::ECDSAsecp256k1);
        let sig_str = "SSMoCSP1ZLh1gQoR9MCdbjoMKwJzg_19rT_WOUCwDKjSYk-H-nPdHvLOBl7DFY7BRFD0Q2WgR7lM8Ygop3e32YJA";
        assert_eq!(id.to_str(), sig_str);
        let id2 = SignatureIdentifier::from_str(sig_str).unwrap();
        assert_eq!(id, id2);
        let result = kp.verify(message.as_bytes(), id2.derivative().as_slice());
        assert!(result.is_ok());
    }
}
