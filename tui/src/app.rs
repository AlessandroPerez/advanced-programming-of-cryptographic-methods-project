use std::error;
use crossterm::event;
use crossterm::event::{Event, KeyEventKind, KeyCode};
use ratatui::{DefaultTerminal, Frame};
use ratatui::backend::Backend;
use client::{Client};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Clear};
use crate::widgets::register::RegistrationWidget;
use crate::widgets::chats::ChatsWidget;
use crate::widgets::popup::PopupWidget;
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
    pub (crate) active_chat: usize,
    pub(crate) show_popup: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum InputMode {
    Normal,
    Insert,
}
impl PartialEq for InputMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (InputMode::Normal, InputMode::Normal) => true,
            (InputMode::Insert, InputMode::Insert) => true,
            _ => false,
        }
    }
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
            active_chat: 0,
            show_popup: false,
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

    fn draw(&mut self, frame: &mut Frame) {

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
                let area = frame.area();
                if self.show_popup {
                    let error_message = match &self.error {
                        Some(e) => e.to_string(),
                        None => String::new(),
                    };
                    let area = popup_area(area, 30, 4);
                    frame.render_widget(Clear, area); //this clears out the background
                    frame.render_widget(PopupWidget::new(
                        self.input.clone(),
                        self.character_index,
                        self.input_mode.clone(),
                        error_message,
                    ), area);
                }
            },
        }
    }

    pub async fn quit(&mut self) {
        self.running = false;
        self.client.disconnect().await;
    }


}

fn popup_area(area: Rect, len_x: u16, len_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(len_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Length(len_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

