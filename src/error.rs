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

//! # Error module.

#![warn(missing_docs)]

use thiserror::Error;

/// Error type.
#[derive(Error, Debug)]
pub enum Error {
    /// Key pair error.
    #[error("Error key pair {0} -> {1}")]
    KeyPair(String, String), // grcov-excl-line
    /// Deserialize Error.
    #[error("Error deserialize {0}")]
    Deserialize(String), // grcov-excl-line
    /// Decode Error.
    #[error("Error decode {0} -> {1}")]
    Decode(String, String), // grcov-excl-line
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_error() {
        let error = Error::KeyPair("a".to_owned(), "b".to_owned());
        assert_eq!(error.to_string(), "Error key pair a -> b");

        let error = Error::Deserialize("a".to_owned());
        assert_eq!(error.to_string(), "Error deserialize a");

        let error = Error::Decode("a".to_owned(), "b".to_owned());
        assert_eq!(error.to_string(), "Error decode a -> b");

    }
}