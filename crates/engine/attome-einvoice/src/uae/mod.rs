//! UAE e-invoicing (roadmap AG3-T2): the PINT AE UBL document ([`pint`])
//! and its sending through an accredited service provider ([`asp`]). The
//! UAE model (five corners) has the supplier's ASP deliver the document to
//! the buyer's ASP and report it to the Federal Tax Authority, so Attome
//! writes the document and hands it to its ASP; it never talks to the FTA.

pub mod asp;
pub mod pint;
