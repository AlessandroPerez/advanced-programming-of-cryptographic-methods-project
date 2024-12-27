use log::{self, error, debug};

mod tui;

pub fn run() {
    debug!("Starting client...");
    if let Err(e) = tui::start_tui() {
        error!("Error starting TUI: {:?}", e);
    }
}
