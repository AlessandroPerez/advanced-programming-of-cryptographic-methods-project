use std::io;
use client::Client;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

mod handler;
mod app;
mod widgets;
mod errors;
pub mod event;
mod tui;
mod ui;

use crate::app::{App, AppResult};
use crate::event::{EventHandler, Event};
use crate::handler::handle_key_events;
use crate::tui::Tui;

#[tokio::main]
async fn main() -> AppResult<()> {

    // TODO: correct known bugs:
    //  1. when press the char 'é' the app crashes
    //  2. disable input when the AppState is Chats and the InputMode is Insert but the active window is 0

    // Init client
    let (chat_tx, chat_rx) = tokio::sync::mpsc::channel(100);
    let client = Client::new(chat_tx).await.unwrap_or_else(|_| {
        eprintln!("Failed to establish the connection with the server");
        std::process::exit(1);
    });

    // Init ratatui
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(250);
    let mut tui = Tui::new(terminal, events);
    tui.init()?;

    // Run app
    let mut app = App::new(client, chat_rx);

    while app.running {

        tui.draw(&mut app)?;
        // Handle events.
        match tui.events.next().await? {
            Event::Tick => app.tick().await,
            Event::Key(key_event) => handle_key_events(key_event, &mut app).await?,
            //Event::Mouse(_) => {}
            //Event::Resize(_, _) => {}
        }
        
    }

    tui.exit()?;
    Ok(())
}