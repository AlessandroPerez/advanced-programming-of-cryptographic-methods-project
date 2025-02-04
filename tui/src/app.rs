use std::error;
use crossterm::event;
use crossterm::event::{Event, KeyEventKind, KeyCode};
use ratatui::{DefaultTerminal, Frame};
use ratatui::backend::Backend;
use client::{Client};
use crate::widgets::register::RegistrationWidget;
use crate::widgets::chats::ChatsWidget;
use crate::errors::TuiError;
use crate::handler::handle_key_events;

// Application result type
pub type AppResult<T> = Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum AppState {
    Animation,

    #[default]
    Register,

    Chats,
}

impl PartialEq for AppState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AppState::Register, AppState::Register) => true,
            (AppState::Chats, AppState::Chats) => true,
            _ => false,
        }
    }
}

pub struct App {
    pub running: bool, // Is the application running?
    pub state: AppState, // Application state

    pub client: Client,

    pub(crate) input: String,
    pub(crate) input_mode: InputMode,
    pub(crate) character_index: usize,
    pub(crate) error: Option<TuiError>,

    pub(crate) active_window: usize,
    pub(crate) selected_chat: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum InputMode {
    Normal,
    Insert,
}

impl App {

    pub(crate) fn new(client: Client) -> Self {
        Self {
            running: true,
            state: AppState::default(),
            client,
            input: String::new(),
            input_mode: InputMode::Insert,
            character_index: 0,
            error: None,
            active_window: 0,
            selected_chat: 0,
        }
    }


    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> AppResult<()> {

        // Main app loop
        while self.running {

            terminal.draw(|frame| self.draw(frame))?;


            handle_key_events(event::read()?, self).await?;
        }

        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {

        match self.state {
            AppState::Animation => {
                //TODO
            },
            AppState::Register => {
                let mut error_message = String::new();
                if let Some(error) = &self.error {
                    error_message = error.to_string();
                }
                frame.render_widget(
                    RegistrationWidget::new(
                        self.input.clone(), // Input
                        error_message, // Error message
                        self.character_index, // Cursor position
                        self.input_mode.clone(), // Current input mode
                    ),
                    frame.area()
                );

            },
            AppState::Chats => {
                frame.render_widget(
                    ChatsWidget::new(
                        self.input.clone(),
                        self.character_index,
                        self.input_mode.clone(),
                        String::from("Marco Wang"),
                        vec![
                            String::from("Item 1"),
                            String::from("Item 2"),
                            String::from("Item 3"),
                        ],
                        self.selected_chat,
                        self.active_window,
                    ),
                    frame.area()
                );
            },
        }
    }

    pub async fn quit(&mut self) {
        self.running = false;
        self.client.disconnect().await;
    }
}