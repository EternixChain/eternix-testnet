//! Approved exact two-stage kernel, isolated from prototype Ticket/ProtocolState and clocks.
use super::*;
use crate::block_commitment::hash_with_domain;

/// Immutable selector observation. Only the independently supplied historical state determines
/// eligibility; bucket draws/peers/candidate fields never install another candidate set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    pub(super) slot: u64,
    pub(super) reference: Hash,
    pub(super) seed: Hash,
    pub(super) total: u64,
    pub(super) bucket: u8,
    pub(super) retry: u64,
    pub(super) raw: u64,
    pub(super) offset: u64,
    pub(super) owner: String,
    pub(super) ticket: u64,
    pub(super) score: Hash,
}
impl Selection {
    /// Exact planned inclusion slot, not local elapsed time.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// Full-genesis N before32, exact canonical H(s−32) thereafter.
    pub fn reference(&self) -> Hash {
        self.reference
    }
    /// Keccak slot seed with the approved exact domain and BE64 slot.
    pub fn seed(&self) -> Hash {
        self.seed
    }
    /// Count of eligible tickets, not the sum of numeric bucket IDs.
    pub fn total_tickets(&self) -> u64 {
        self.total
    }
    /// Chosen physical ACTIVE bucket in increasing cumulative order.
    pub fn bucket(&self) -> u8 {
        self.bucket
    }
    /// Accepted rejection-sampling retry number, starting at0.
    pub fn retry(&self) -> u64 {
        self.retry
    }
    /// First eight accepted Keccak bytes interpreted unsigned BE.
    pub fn raw(&self) -> u64 {
        self.raw
    }
    /// Uniform cumulative-ticket offset; it selects a bucket, not an input ticket row.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Exact selected closed validator ID.
    pub fn producer(&self) -> &str {
        &self.owner
    }
    /// Globally unique selected ticket ID.
    pub fn ticket_id(&self) -> u64 {
        self.ticket
    }
    /// Lowest score within the selected bucket; ticket ID breaks equal-score ties.
    pub fn score(&self) -> Hash {
        self.score
    }
}

pub(super) fn select_inputs(
    reference: Hash,
    slot: u64,
    validators: &[Validator],
    tickets: &[Ticket],
) -> Result<Selection, Error> {
    state::validate_eligibility(validators, tickets)?;
    if !(1..=MAX_SLOTS).contains(&slot) {
        return Err(Error::ExperimentLimit);
    }
    let mut pre = Vec::from(reference);
    pre.extend_from_slice(&slot.to_be_bytes());
    let seed = hash_with_domain(b"eternix:leader-selection:v1", &pre);
    let eligible: Vec<_> = tickets
        .iter()
        .filter(|t| {
            t.status == TicketStatus::Active
                && validators
                    .iter()
                    .any(|v| v.id == t.owner && v.status == ValidatorStatus::Active)
        })
        .collect();
    let mut counts = [0u64; 256];
    for t in &eligible {
        counts[t.bucket as usize] = counts[t.bucket as usize]
            .checked_add(1)
            .ok_or(Error::Overflow)?;
    }
    let total = (2..256).try_fold(0u64, |sum, i| {
        sum.checked_add(counts[i]).ok_or(Error::Overflow)
    })?;
    if total == 0 {
        return Err(Error::NoEligibleTickets);
    }
    let (retry, raw, offset) = draw(seed, total)?;
    let mut remaining = offset;
    let mut bucket = None;
    for b in 2u16..=255 {
        if remaining < counts[b as usize] {
            bucket = Some(b as u8);
            break;
        }
        remaining = remaining
            .checked_sub(counts[b as usize])
            .ok_or(Error::Overflow)?;
    }
    let bucket = bucket.ok_or(Error::State("cumulative bucket"))?;
    let (score, ticket, owner) = best(eligible.iter().filter(|t| t.bucket == bucket).map(|t| {
        let mut p = Vec::from(seed);
        p.extend_from_slice(&t.id.to_be_bytes());
        (
            hash_with_domain(b"eternix:ticket-selection:v1", &p),
            t.id,
            t.owner.as_str(),
        )
    }))
    .ok_or(Error::State("chosen bucket empty"))?;
    Ok(Selection {
        slot,
        reference,
        seed,
        total,
        bucket,
        retry,
        raw,
        offset,
        owner: owner.into(),
        ticket,
        score,
    })
}
pub(super) fn best<'a>(
    candidates: impl Iterator<Item = (Hash, u64, &'a str)>,
) -> Option<(Hash, u64, &'a str)> {
    candidates.min_by_key(|(score, id, _)| (*score, *id))
}
fn draw(seed: Hash, total: u64) -> Result<(u64, u64, u64), Error> {
    draw_with(total, |retry| {
        let mut p = Vec::from(seed);
        p.extend_from_slice(&retry.to_be_bytes());
        let h = hash_with_domain(b"eternix:bucket-selection:v1", &p);
        u64::from_be_bytes(h[..8].try_into().expect("eight digest bytes"))
    })
}
// Separate deterministic source permits meaningful rejection-branch tests without pretending to
// have found a natural Keccak raw0 or weakening the production retry behavior.
pub(super) fn draw_with(
    total: u64,
    mut raw: impl FnMut(u64) -> u64,
) -> Result<(u64, u64, u64), Error> {
    if total == 0 {
        return Err(Error::NoEligibleTickets);
    }
    let threshold = total.wrapping_neg() % total;
    let mut retry = 0;
    loop {
        let n = raw(retry);
        if n >= threshold {
            return Ok((retry, n, n % total));
        }
        retry = retry.checked_add(1).ok_or(Error::Overflow)?;
    }
}
