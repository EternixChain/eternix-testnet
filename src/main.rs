mod app;
mod config;
mod leader_selection;
mod models;
mod p2p;
mod rpc;
mod ui;

use std::io;
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
use crate::rpc::start_rpc_server;

fn main() -> Result<()> {
    let cfg = parse_args()?;
    let mut terminal = init_terminal()?;
    let rpc_rx = start_rpc_server(cfg.rpc_port);
    let mut app = Protocol::new(cfg)?;
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

        while let Ok(env) = rpc_rx.try_recv() {
            let out = app.handle_rpc(env.req);
            let _ = env.reply.send(out);
        }

        app.tick();
    }

    restore_terminal(terminal)?;
    Ok(())
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
