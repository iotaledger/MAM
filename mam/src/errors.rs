use alloc::string::String;

#[derive(Eq, PartialEq, Debug)]
pub enum MamError {
    /// Message Hash did not have any hamming weight of zero
    InvalidHash,
    /// Signature did not match expected root
    InvalidSignature,
    /// Array was too short
    ArrayOutOfBounds,
    /// Custom error
    CustomError(String),
}
