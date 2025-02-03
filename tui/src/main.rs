use std::io;
use client::Client;

mod handler;
mod app;
mod widgets;
mod errors;

use crate::app::{App, AppResult};

#[tokio::main]
async fn main() -> AppResult<()> {

    // Init client
    let client = Client::new().await.unwrap_or_else(|_| {
        eprintln!("Failed to establish the connection with the server");
        std::process::exit(1);
    });

    // Init ratatui
    let mut terminal = ratatui::init();

    // Run app
    let app_result = App::new(client).run(&mut terminal).await;
    // Restore terminal
    ratatui::restore();

    // Exit code of the app
    app_result
}