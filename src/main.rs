mod app;
mod config;
mod leader_selection;
mod models;
mod p2p;
mod rpc;
mod ui;

use std::io;
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::DefaultTerminal;

use crate::app::Protocol;
use crate::config::parse_args;
use crate::rpc::{RpcEnvelope, start_rpc_server};

fn main() -> Result<()> {
    let cfg = parse_args()?;
    let no_tui = cfg.no_tui;
    let rpc_rx = start_rpc_server(cfg.rpc_port);
    let app = Protocol::new(cfg)?;

    if no_tui {
        eprintln!("Eternix node running without TUI; stop with Ctrl+C");
        run_headless(app, rpc_rx)
    } else {
        run_tui(app, rpc_rx)
    }
}

fn run_tui(mut app: Protocol, rpc_rx: Receiver<RpcEnvelope>) -> Result<()> {
    let mut terminal = init_terminal()?;
    let tick = Duration::from_millis(50);

    loop {
        terminal.draw(|f| ui::render(f, &app))?;

        if event::poll(tick)?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('n') => app.seed_normal_tx(true),
                KeyCode::Char('b') => app.seed_pbm_tx(),
                KeyCode::Char('r') => app.request_local_ticket_retire(1),
                _ => {}
            }
        }

        process_rpc(&mut app, &rpc_rx);
        app.tick();
    }

    restore_terminal(terminal)?;
    Ok(())
}

fn run_headless(mut app: Protocol, rpc_rx: Receiver<RpcEnvelope>) -> Result<()> {
    let tick = Duration::from_millis(50);
    loop {
        process_rpc(&mut app, &rpc_rx);
        app.tick();
        thread::sleep(tick);
    }
}

fn process_rpc(app: &mut Protocol, rpc_rx: &Receiver<RpcEnvelope>) {
    while let Ok(env) = rpc_rx.try_recv() {
        let out = app.handle_rpc(env.req);
        let _ = env.reply.send(out);
    }
}

fn init_terminal() -> Result<DefaultTerminal> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    Ok(ratatui::init())
}

fn restore_terminal(mut terminal: DefaultTerminal) -> Result<()> {
    ratatui::restore();
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
