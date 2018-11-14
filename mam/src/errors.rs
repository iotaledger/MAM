use alloc::string::String;

#[derive(Eq, PartialEq, Debug)]
#[repr(C)]
pub enum MamError {
    None,
    /// Message Hash did not have any hamming weight of zero
    InvalidHash,
    /// Signature did not match expected root
    InvalidSignature,
    /// Array was too short
    ArrayOutOfBounds,
}
