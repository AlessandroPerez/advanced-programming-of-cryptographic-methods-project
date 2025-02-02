use std::io;
use std::error;
use crossterm::event;
use crossterm::event::{Event, KeyEventKind};
use ratatui::{DefaultTerminal, Frame};
use ratatui::backend::Backend;
use crate::handler::handle_key_events;
use client::{Client};



// Application result type
pub type AppResult<T> = Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone, Copy, Default)]
enum AppState {
    #[default]
    Animation,

    Register,
    Chats,
}

pub struct App {
    pub running: bool, // Is the application running?
    pub state: AppState, // Application state

    pub client: Client,
}

impl App {

    pub(crate) fn new(client: Client) -> Self {
        Self {
            running: true,
            state: AppState::default(),
            client: client
        }
    }

    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> AppResult<()> {

        // Main app loop
        while self.running {

            terminal.draw(|frame| self.draw(frame))?;

            match event::read()? {
                Event::Key(key_event) if key_event.kind == KeyEventKind::Press => handle_key_events(key_event, self)?,
                Event::Mouse(_) => {},
                Event::Resize(_, _) => {},
                _ => {}
            }
        }

        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {

        match self.state {
            AppState::Animation => {
                //TODO
            },
            AppState::Register => {
                //TODO
            },
            AppState::Chats => {
                //TODO
            },
        }
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}