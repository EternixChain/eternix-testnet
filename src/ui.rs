use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Wrap};

use crate::app::Protocol;
use crate::models::{
    BlockKind, FINALITY_WINDOW_SLOTS, Mode, NodeMode, SLOT_MS, SUB_EPOCH_SLOTS, ValidatorState,
};

pub fn render(frame: &mut Frame, app: &Protocol) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(80),
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(root[0]);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(50),
            Constraint::Percentage(25),
        ])
        .split(main[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(50),
            Constraint::Percentage(25),
        ])
        .split(main[1]);

    render_validator_panel(frame, app, top[0]);
    render_slot_panel(frame, app, top[1]);
    render_network_panel(frame, app, top[2]);
    render_rewards_panel(frame, app, bottom[0]);
    render_history_panel(frame, app, bottom[1]);
    render_mempool_panel(frame, app, bottom[2]);
    render_liveness_bar(frame, app, root[1]);
    render_events_panel(frame, app, root[2]);
    render_controls(frame, root[3]);
}

fn render_validator_panel(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    let role = match st.mode_local {
        NodeMode::Validator => "Validator",
        NodeMode::Standard => "Non-validator",
    };
    let local = st
        .local_validator_id
        .as_ref()
        .and_then(|id| st.validators.iter().find(|v| &v.id == id));
    let ticket_count = if let Some(id) = &st.local_validator_id {
        st.tickets.iter().filter(|t| &t.owner == id).count()
    } else {
        0
    };
    let total_tickets = st.tickets.len();
    let retiring_count = if let Some(id) = &st.local_validator_id {
        st.tickets
            .iter()
            .filter(|t| &t.owner == id && t.retiring)
            .count()
    } else {
        0
    };
    let ticket_pct = if total_tickets > 0 {
        ticket_count as f64 * 100.0 / total_tickets as f64
    } else {
        0.0
    };

    let state = local
        .map(|v| format_validator_state(v.state))
        .unwrap_or("N/A");
    let validator_account = local
        .and_then(|v| v.owner_account.as_deref())
        .unwrap_or("N/A");
    let vault = local.map(|v| v.vault_quarks).unwrap_or(0);
    let miss = local.map(|v| v.miss_counter).unwrap_or(0);

    let lines = vec![
        Line::from(format!("Role: {}", role)),
        Line::from(format!("Validator Account: {}", validator_account)),
        Line::from(format!("State: {}", state)),
        Line::from(format!("Tickets: {}", ticket_count)),
        Line::from(format!("Ticket Share: {:.2}%", ticket_pct)),
        Line::from(format!("Retiring: {}", retiring_count)),
        Line::from(format!("Vault: {}", format_etx(vault))),
        Line::from(format!("Miss Counter: {}", miss)),
        Line::from(format!("Next Chance: {:.2}%", ticket_pct)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("User / Validator")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_slot_panel(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    let elapsed = st.slot_started.elapsed().as_millis() as u64;
    let ratio = (elapsed as f64 / SLOT_MS as f64).clamp(0.0, 1.0);

    let (result, result_style) = if let Some(r) = &st.current_result {
        match r.kind {
            BlockKind::Validator => (
                "Validator block".to_string(),
                Style::default().fg(Color::Green),
            ),
            BlockKind::ProtocolMiss => (
                "Protocol block (Miss)".to_string(),
                Style::default().fg(Color::Red),
            ),
            BlockKind::ProtocolCollision => (
                "Protocol block (Collision)".to_string(),
                Style::default().fg(Color::Yellow),
            ),
            BlockKind::ProtocolNoTickets => (
                "Protocol block (No tickets)".to_string(),
                Style::default().fg(Color::Yellow),
            ),
        }
    } else {
        ("Pending".to_string(), Style::default().fg(Color::Gray))
    };

    let tx = st.current_result.as_ref().map(|r| r.tx_count).unwrap_or(0);
    let gas = st.current_result.as_ref().map(|r| r.gas_used).unwrap_or(0);
    let mode = match st.mode {
        Mode::Normal => "NORMAL",
        Mode::Pbm => "PBM",
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(2)])
        .split(area);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("Slot: {}", st.slot)),
            Line::from(format!("Elapsed: {} ms / {} ms", elapsed, SLOT_MS)),
            Line::from(format!("Leader: {}", st.current_leader)),
            Line::from(format!("Execution: {:?}", st.exec_status)),
            Line::from(vec![Span::styled(
                format!("Result: {}", result),
                result_style,
            )]),
            Line::from(format!("Tx Count: {}", tx)),
            Line::from(format!("Gas Used: {}", gas)),
            Line::from(format!("Mode: {}", mode)),
            Line::from(format!("Finality Window: {} slots", FINALITY_WINDOW_SLOTS)),
        ])
        .block(
            Block::default()
                .title("Slot View")
                .borders(Borders::ALL)
                .border_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .wrap(Wrap { trim: true }),
        chunks[0],
    );

    frame.render_widget(
        Gauge::default()
            .ratio(ratio)
            .label(format!("{:.1}%", ratio * 100.0))
            .gauge_style(Style::default().fg(Color::Blue))
            .use_unicode(true),
        chunks[1],
    );
}

fn render_network_panel(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    let role = match st.mode_local {
        NodeMode::Validator => "Validator Node",
        NodeMode::Standard => "Full Node",
    };
    let node_id = st
        .local_validator_id
        .clone()
        .unwrap_or_else(|| "node-standard".to_string());

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("Peers: {}", app.p2p.peer_count())),
            Line::from(format!("Sync: {:.2}%", st.sync_pct)),
            Line::from("Latency: n/a"),
            Line::from(format!("Node ID: {}", node_id)),
            Line::from(format!("Node Role: {}", role)),
            Line::from("Slot Drift: 0"),
        ])
        .block(
            Block::default()
                .title("Network / Node")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_rewards_panel(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    let sub_slot = st.slot % SUB_EPOCH_SLOTS;
    let sub_epoch_start = st.slot.saturating_sub(sub_slot);
    let mut subepoch_total = 0_u64;
    let mut subepoch_validator = 0_u64;
    for h in st.history.iter() {
        if h.slot >= sub_epoch_start {
            subepoch_total += 1;
            if h.kind == BlockKind::Validator {
                subepoch_validator += 1;
            }
        }
    }

    let observed_validator_ratio = if subepoch_total > 0 {
        subepoch_validator as f64 / subepoch_total as f64
    } else {
        0.0
    };
    let projected_validator_blocks =
        (observed_validator_ratio * SUB_EPOCH_SLOTS as f64).round() as u64;
    let est_offset_per_block = if projected_validator_blocks > 0 {
        st.burn_offset_k_permille as u128 * st.burn_this_sub_epoch
            / 1000
            / projected_validator_blocks as u128
    } else {
        0
    };
    let local_est_reward = if let Some(id) = &st.local_validator_id {
        let produced_by_local = st
            .blocks_this_sub_epoch
            .iter()
            .filter(|p| p.as_ref().is_some_and(|x| x == id))
            .count() as u128;
        app.base_reward_per_block_quarks()
            .saturating_add(est_offset_per_block)
            .saturating_mul(produced_by_local)
    } else {
        0
    };
    let total_supply = app.total_supply_quarks();
    let sub_epoch_trend = supply_trend(st.sub_epoch_issued_quarks, st.sub_epoch_burned_quarks);
    let epoch_trend = supply_trend(st.epoch_issued_quarks, st.epoch_burned_quarks);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                "Inflation: {:.2}%",
                st.annual_inflation_ppb as f64 / 10_000_000.0
            )),
            Line::from(format!(
                "Base Reward/Block: {}",
                format_etx(app.base_reward_per_block_quarks())
            )),
            Line::from(format!(
                "Burn-offset k: {:.3}",
                st.burn_offset_k_permille as f64 / 1000.0
            )),
            Line::from(format!("Sub-epoch: {}/{}", sub_slot, SUB_EPOCH_SLOTS)),
            Line::from(format!(
                "Fee Burn Accumulated: {}",
                format_etx(st.burn_this_sub_epoch)
            )),
            Line::from(format!(
                "Est Offset/Block: {}",
                format_etx(est_offset_per_block)
            )),
            Line::from(format!(
                "Est Validator Reward: {}",
                format_etx(local_est_reward)
            )),
            Line::from(format!(
                "Base Issuance Total: {}",
                format_etx(st.base_issuance_total)
            )),
            Line::from(format!(
                "Burn-offset Total: {}",
                format_etx(st.burn_offset_total)
            )),
            Line::from(format!(
                "Fees Burned Total: {}",
                format_etx(st.fees_burned_total)
            )),
            Line::from(format!(
                "Ticket Burns Total: {}",
                format_etx(st.ticket_burned_total)
            )),
            Line::from(format!("Total Supply: {}", format_etx(total_supply))),
            Line::from(format!(
                "Net Supply Change This Sub-epoch: {} - {}",
                format_signed_supply_change(st.sub_epoch_issued_quarks, st.sub_epoch_burned_quarks),
                sub_epoch_trend
            )),
            Line::from(format!(
                "Net Supply Change This Epoch: {} - {}",
                format_signed_supply_change(st.epoch_issued_quarks, st.epoch_burned_quarks),
                epoch_trend
            )),
        ])
        .block(
            Block::default()
                .title("Rewards / Economy")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_history_panel(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    let rows = st.history.iter().take(10).map(|h| {
        let symbol = match h.kind {
            BlockKind::Validator => "✓",
            BlockKind::ProtocolMiss => "P(miss)",
            BlockKind::ProtocolCollision => "P(coll)",
            BlockKind::ProtocolNoTickets => "P(none)",
        };
        Row::new(vec![
            Cell::from(h.slot.to_string()),
            Cell::from(h.leader.clone()),
            Cell::from(symbol),
        ])
    });

    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(16),
                Constraint::Min(10),
            ],
        )
        .header(Row::new(vec!["slot", "leader", "result"]).style(Style::default().fg(Color::Cyan)))
        .block(Block::default().title("Slot History").borders(Borders::ALL)),
        area,
    );
}

fn render_mempool_panel(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    let transfer = st.mempool.iter().filter(|tx| tx.kind == "transfer").count();
    let contract = st.mempool.iter().filter(|tx| tx.kind == "contract").count();
    let system = st
        .mempool
        .iter()
        .filter(|tx| {
            matches!(
                tx.kind,
                "system" | "registerValidator" | "buyTicket" | "walletToVault" | "vaultToWallet"
            )
        })
        .count();
    let last_tx = st.current_result.as_ref().map(|r| r.tx_count).unwrap_or(0);
    let last_gas = st.current_result.as_ref().map(|r| r.gas_used).unwrap_or(0);
    let last_fees = st
        .current_result
        .as_ref()
        .map(|r| r.fees_burned)
        .unwrap_or(0);

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("Mempool Size: {}", st.mempool.len())),
            Line::from(format!("Transfer: {}", transfer)),
            Line::from(format!("Contract: {}", contract)),
            Line::from(format!("System: {}", system)),
            Line::from(format!("Last Block Tx: {}", last_tx)),
            Line::from(format!("Last Block Gas: {}", last_gas)),
            Line::from(format!(
                "Last Block Fees Burned: {}",
                format_etx(last_fees as u128)
            )),
        ])
        .block(Block::default().title("Mempool").borders(Borders::ALL))
        .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_liveness_bar(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    if st.mode == Mode::Pbm {
        frame.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                "PBM ACTIVE",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]))
            .block(Block::default().title("Liveness").borders(Borders::ALL)),
            area,
        );
        return;
    }

    let pct = if st.epoch_total_slots == 0 {
        0.0
    } else {
        st.epoch_validator_blocks as f64 * 100.0 / st.epoch_total_slots as f64
    };
    let mut recent = String::new();
    for h in st.history.iter().take(18) {
        recent.push_str(match h.kind {
            BlockKind::Validator => "✓ ",
            _ => "P ",
        });
    }

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("Validator Liveness: {:.2}%", pct)),
            Line::from(format!("Recent: {}", recent.trim_end())),
        ])
        .block(Block::default().title("Liveness").borders(Borders::ALL)),
        area,
    );
}

fn render_events_panel(frame: &mut Frame, app: &Protocol, area: ratatui::layout::Rect) {
    let st = &app.state;
    let mut lines = Vec::new();
    for e in st.events.iter().take(10) {
        lines.push(Line::from(e.clone()));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("Events").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_controls(frame: &mut Frame, area: ratatui::layout::Rect) {
    frame.render_widget(
        Paragraph::new("controls: q quit | n add tx | b add pbm tx | r retire ticket")
            .style(Style::default().fg(Color::Gray)),
        area,
    );
}

fn format_validator_state(state: ValidatorState) -> &'static str {
    match state {
        ValidatorState::Active => "ACTIVE",
        ValidatorState::PausedLowVault => "PAUSED_LOW_VAULT",
        ValidatorState::PunishedCooldown => "PUNISHED_COOLDOWN",
        ValidatorState::Inactive => "INACTIVE_VALIDATOR",
        ValidatorState::Jailed => "JAILED",
    }
}

fn format_etx(quarks: u128) -> String {
    let whole = quarks / 10_000_000_000;
    let fractional = quarks % 10_000_000_000;
    format!("{}.{:010} ETX", format_with_commas(whole), fractional)
}

fn format_signed_supply_change(issued_quarks: u128, burned_quarks: u128) -> String {
    if burned_quarks > issued_quarks {
        format!("-{}", format_etx(burned_quarks - issued_quarks))
    } else {
        format!("+{}", format_etx(issued_quarks - burned_quarks))
    }
}

fn supply_trend(issued_quarks: u128, burned_quarks: u128) -> &'static str {
    if burned_quarks > issued_quarks {
        "deflationary"
    } else if issued_quarks > burned_quarks {
        "inflationary"
    } else {
        "neutral"
    }
}

fn format_with_commas(value: u128) -> String {
    let raw = value.to_string();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (i, ch) in raw.chars().enumerate() {
        if i > 0 && (raw.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}
