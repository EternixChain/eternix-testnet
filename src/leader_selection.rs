use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::models::Ticket;

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

fn select_bucket(seed: [u8; 32], bucket_counts: &HashMap<u8, usize>) -> Option<u8> {
    let mut best_bucket: Option<u8> = None;
    let mut best_score: Option<u128> = None;

    for (&bucket_id, &count) in bucket_counts {
        if count == 0 {
            continue;
        }
        let mut data = Vec::new();
        data.extend_from_slice(&seed);
        data.extend_from_slice(&(bucket_id as u64).to_be_bytes());
        let hash = hash_bytes(&data);
        let raw = u128::from_be_bytes(hash[0..16].try_into().ok()?);
        let score = raw / count as u128;

        match best_score {
            None => {
                best_bucket = Some(bucket_id);
                best_score = Some(score);
            }
            Some(current) => {
                if (score, bucket_id) < (current, best_bucket.unwrap_or(bucket_id)) {
                    best_bucket = Some(bucket_id);
                    best_score = Some(score);
                }
            }
        }
    }

    best_bucket
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

    let mut bucket_counts: HashMap<u8, usize> = HashMap::new();
    for t in eligible_tickets {
        *bucket_counts.entry(t.bucket).or_insert(0) += 1;
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
