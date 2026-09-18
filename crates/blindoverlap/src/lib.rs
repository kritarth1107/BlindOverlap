//! BlindOverlap: Agent-native private set intersection (PSI) over content-addressed fact IDs.
//!
//! Two agents compare memories. Only the overlap comes out.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod fact_id;
pub mod protocol;
pub mod receipt;
pub mod wire;

pub use fact_id::{
    canonical_json, fact_id_from_json, fact_id_from_str, FactId, FactIdError, FactSet,
};
pub use protocol::{
    IntersectionMode, MaskedElement, PsiError, PsiParty, PsiProtocol, PsiResult, MAX_SET_SIZE,
};
pub use receipt::{IntersectionReceipt, ReceiptError, ReceiptMode, ReceiptSigner, ReceiptVerifier};
pub use wire::{
    decode as wire_decode, encode as wire_encode, encode_pretty as wire_encode_pretty,
    IntersectionReveal, MaskedSetOffer, MaskedSetReply, WireError, WireMessage,
};
