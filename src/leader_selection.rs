use sha2::{Digest, Sha256};

use crate::models::Ticket;

const BUCKET_SELECTION_DOMAIN: &[u8] = b"eternix:bucket-selection:v1";

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn slot_seed(epoch_seed: [u8; 32], slot_index: u64) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&epoch_seed);
    data.extend_from_slice(&slot_index.to_be_bytes());
    hash_bytes(&data)
}

fn uniform_below(seed: [u8; 32], upper_bound: u64) -> Option<u64> {
    if upper_bound == 0 {
        return None;
    }

    let threshold = upper_bound.wrapping_neg() % upper_bound;
    let mut retry = 0_u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(BUCKET_SELECTION_DOMAIN);
        hasher.update(seed);
        hasher.update(retry.to_be_bytes());
        let hash = hasher.finalize();
        // The first eight SHA-256 bytes form the uniform source value in big-endian order.
        let raw = u64::from_be_bytes(hash[..8].try_into().ok()?);
        if raw >= threshold {
            return Some(raw % upper_bound);
        }
        retry = retry.checked_add(1)?;
    }
}

fn bucket_for_offset(bucket_counts: &[u64; 256], mut offset: u64) -> Option<u8> {
    for bucket_id in 2u16..=255 {
        let count = bucket_counts[bucket_id as usize];
        if offset < count {
            return Some(bucket_id as u8);
        }
        offset = offset.checked_sub(count)?;
    }
    None
}

fn select_bucket(seed: [u8; 32], bucket_counts: &[u64; 256]) -> Option<u8> {
    let total_active = (2u16..=255).try_fold(0_u64, |total, bucket_id| {
        total.checked_add(bucket_counts[bucket_id as usize])
    })?;
    let offset = uniform_below(seed, total_active)?;
    bucket_for_offset(bucket_counts, offset)
}

fn select_ticket(seed: [u8; 32], ticket_ids: &[u64]) -> Option<u64> {
    let mut best_ticket: Option<u64> = None;
    let mut best_score: Option<[u8; 32]> = None;

    for &ticket_id in ticket_ids {
        let mut data = Vec::new();
        data.extend_from_slice(&seed);
        data.extend_from_slice(&ticket_id.to_be_bytes());
        let hash = hash_bytes(&data);

        match best_score {
            None => {
                best_ticket = Some(ticket_id);
                best_score = Some(hash);
            }
            Some(current) => {
                if (hash, ticket_id) < (current, best_ticket.unwrap_or(ticket_id)) {
                    best_ticket = Some(ticket_id);
                    best_score = Some(hash);
                }
            }
        }
    }

    best_ticket
}

pub fn select_leader_owner(
    epoch_seed: [u8; 32],
    slot_index: u64,
    eligible_tickets: &[&Ticket],
) -> Option<String> {
    if eligible_tickets.is_empty() {
        return None;
    }

    let seed = slot_seed(epoch_seed, slot_index);

    let mut bucket_counts = [0u64; 256];
    for t in eligible_tickets {
        if t.bucket < 2 {
            continue;
        }
        let count = &mut bucket_counts[t.bucket as usize];
        *count = count.checked_add(1)?;
    }

    let chosen_bucket = select_bucket(seed, &bucket_counts)?;
    let bucket_ticket_ids: Vec<u64> = eligible_tickets
        .iter()
        .filter(|t| t.bucket == chosen_bucket)
        .map(|t| t.id)
        .collect();
    let winner_ticket_id = select_ticket(seed, &bucket_ticket_ids)?;

    eligible_tickets
        .iter()
        .find(|t| t.id == winner_ticket_id)
        .map(|t| t.owner.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tickets_returns_none() {
        assert_eq!(select_leader_owner([0; 32], 0, &[]), None);
    }

    #[test]
    fn dead_and_muted_buckets_are_never_selected() {
        let mut counts = [0u64; 256];
        counts[0] = u64::MAX;
        counts[1] = u64::MAX;
        assert_eq!(select_bucket([1; 32], &counts), None);

        counts[2] = 1;

        assert_eq!(select_bucket([1; 32], &counts), Some(2));
    }

    #[test]
    fn active_ticket_count_overflow_returns_none() {
        let mut counts = [0u64; 256];
        counts[2] = u64::MAX;
        counts[3] = 1;

        assert_eq!(select_bucket([1; 32], &counts), None);
    }

    #[test]
    fn single_populated_active_bucket_is_always_selected() {
        let mut counts = [0u64; 256];
        counts[255] = 17;

        for slot in 0..32 {
            assert_eq!(select_bucket(slot_seed([2; 32], slot), &counts), Some(255));
        }
    }

    #[test]
    fn cumulative_offsets_map_to_exact_bucket_ranges() {
        let mut counts = [0u64; 256];
        counts[2] = 1;
        counts[3] = 2;
        counts[255] = 1;

        assert_eq!(bucket_for_offset(&counts, 0), Some(2));
        assert_eq!(bucket_for_offset(&counts, 1), Some(3));
        assert_eq!(bucket_for_offset(&counts, 2), Some(3));
        assert_eq!(bucket_for_offset(&counts, 3), Some(255));
        assert_eq!(bucket_for_offset(&counts, 4), None);
    }

    #[test]
    fn uniform_below_stays_within_representative_bounds() {
        let bounds = [1, 2, 3, 10, 255, 256, u32::MAX as u64, u64::MAX];
        for upper_bound in bounds {
            for slot in 0..32 {
                let value = uniform_below(slot_seed([3; 32], slot), upper_bound).unwrap();
                assert!(value < upper_bound);
            }
        }
        assert_eq!(uniform_below([0; 32], 0), None);
    }
}
