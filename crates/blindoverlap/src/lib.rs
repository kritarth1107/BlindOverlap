//! BlindOverlap: Agent-native private set intersection (PSI) over content-addressed fact IDs.
//!
//! Two agents compare memories. Only the overlap comes out.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod abort;
pub mod fact_id;
pub mod freshness;
pub mod identity;
pub mod invite;
pub mod lease;
pub mod padding;
pub mod peerbook;
pub mod protocol;
pub mod receipt;
pub mod replay;
pub mod seal;
pub mod session;
pub mod wire;

pub use abort::{AbortError, AbortReason, AbortReceipt, ABORT_RECEIPT_DOMAIN};
pub use fact_id::{
    canonical_json, fact_id_from_json, fact_id_from_str, FactId, FactIdError, FactSet,
};
pub use freshness::{
    current_unix_time, FreshnessError, SessionDeadline, SessionNonce, TranscriptDigest,
    DEFAULT_TTL_SECS,
};
pub use identity::{IdentityError, PartyIdentity, PublicIdentity, IDENTITY_DOMAIN};
pub use invite::{
    AllowedMode, InviteError, InviteTicket, DEFAULT_TICKET_TTL_SECS, INVITE_TICKET_DOMAIN,
};
pub use lease::{LeaseError, SessionLease, DEFAULT_LEASE_TTL_SECS, SESSION_LEASE_DOMAIN};
pub use padding::{
    generate_dummy_fact_ids, generate_dummy_masked_elements, next_power_of_two, pad_fact_ids,
    pad_masked_elements, strip_padding, PaddingConfig, PaddingError,
};
pub use peerbook::{PeerBookError, TrustedPeer, TrustedPeerBook};
pub use protocol::{
    IntersectionMode, MaskedElement, PsiError, PsiParty, PsiProtocol, PsiResult, MAX_SET_SIZE,
};
pub use receipt::{
    IntersectionReceipt, ReceiptError, ReceiptMode, ReceiptSigner, ReceiptVerifier,
    WireBoundReceipt,
};
pub use replay::{PersistentReplayStore, ReplayStore, ReplayStoreError};
pub use seal::{
    MessageDirection, RecordSeal, SealError, SealedSessionBuilder, SealedSessionRecord,
    SessionStatus, WireMessageEntry, SEALED_RECORD_DOMAIN,
};
pub use session::{
    require_peer_trusted, ChannelBinding, InitiatorSession, InitiatorState, ResponderSession,
    ResponderState, SessionConfig, SessionError,
};
pub use wire::{
    decode as wire_decode, decode_signed as wire_decode_signed,
    decode_signed_from_peer as wire_decode_signed_from_peer, encode as wire_encode,
    encode_pretty as wire_encode_pretty, encode_signed as wire_encode_signed,
    encode_signed_pretty as wire_encode_signed_pretty, AbortMessage, IntersectionReveal,
    MaskedSetOffer, MaskedSetReply, SignedWireMessage, WireError, WireMessage,
};
