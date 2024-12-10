use std::fmt;

/// The default URL for the proof network explorer.
pub const DEFAULT_EXPLORER_URL: &str = "https://network.succinct.xyz";

/// A 32-byte hash that uniquely identifies a proof request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(Vec<u8>);

/// A 32-byte hash that uniquely identifies a program.
///
/// This hash is generated by the program's verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKeyHash(Vec<u8>);

/// A 32-byte hash that uniquely identifies a transaction.
///
/// Any mutating operation on the network will produce a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionHash(Vec<u8>);

pub trait HashType: Sized {
    fn new(bytes: Vec<u8>) -> Self;
    fn as_bytes(&self) -> &[u8];
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.as_bytes()))
    }
    fn explorer_path(&self) -> &str;
    fn explorer_url(&self) -> String {
        format!("{}{}/{}", DEFAULT_EXPLORER_URL, self.explorer_path(), self.to_hex())
    }
}

impl HashType for RequestId {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    fn explorer_path(&self) -> &str {
        "/request"
    }
}

impl HashType for VerifyingKeyHash {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    fn explorer_path(&self) -> &str {
        "/program"
    }
}

impl HashType for TransactionHash {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    fn explorer_path(&self) -> &str {
        "/transaction"
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for VerifyingKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for TransactionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
