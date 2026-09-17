//! BlindOverlap: Agent-native private set intersection (PSI) over content-addressed fact IDs.
//!
//! Two agents compare memories. Only the overlap comes out.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod fact_id;
pub mod protocol;
pub mod receipt;

pub use fact_id::{FactId, FactSet};
pub use protocol::{IntersectionMode, PsiProtocol, PsiResult};
pub use receipt::{IntersectionReceipt, ReceiptSigner, ReceiptVerifier};
