//! BlindOverlap: Agent-native private set intersection (PSI) over content-addressed fact IDs.
//!
//! Two agents compare memories. Only the overlap comes out.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod fact_id;
pub mod freshness;
pub mod padding;
pub mod protocol;
pub mod receipt;
pub mod session;
pub mod wire;

pub use fact_id::{
    canonical_json, fact_id_from_json, fact_id_from_str, FactId, FactIdError, FactSet,
};
pub use padding::{
    generate_dummy_fact_ids, generate_dummy_masked_elements, next_power_of_two, pad_fact_ids,
    pad_masked_elements, strip_padding, PaddingConfig, PaddingError,
};
pub use protocol::{
    IntersectionMode, MaskedElement, PsiError, PsiParty, PsiProtocol, PsiResult, MAX_SET_SIZE,
};
pub use receipt::{IntersectionReceipt, ReceiptError, ReceiptMode, ReceiptSigner, ReceiptVerifier};
pub use session::{
    InitiatorSession, InitiatorState, ResponderSession, ResponderState, SessionError,
};
pub use wire::{
    decode as wire_decode, encode as wire_encode, encode_pretty as wire_encode_pretty,
    IntersectionReveal, MaskedSetOffer, MaskedSetReply, WireError, WireMessage,
};
pub use freshness::{
    current_unix_time, FreshnessError, SessionDeadline, SessionNonce, TranscriptDigest,
    DEFAULT_TTL_SECS,
};
