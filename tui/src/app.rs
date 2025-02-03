use std::error;
use crossterm::event;
use crossterm::event::{Event, KeyEventKind, KeyCode};
use ratatui::{DefaultTerminal, Frame};
use ratatui::backend::Backend;
use client::{Client};
use crate::widgets::register::RegistrationWidget;
use crate::errors::TuiError;

// Application result type
pub type AppResult<T> = Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone, Copy, Default)]
enum AppState {
    Animation,

    #[default]
    Register,

    Chats,
}

pub struct App {
    pub running: bool, // Is the application running?
    pub state: AppState, // Application state

    pub client: Client,

    input: String,
    input_mode: InputMode,
    character_index: usize,
    error: Option<TuiError>,
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
        }
    }

    fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.character_index.saturating_sub(1);
        self.character_index = self.clamp_cursor(cursor_moved_left);
    }

    fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.character_index.saturating_add(1);
        self.character_index = self.clamp_cursor(cursor_moved_right);
    }

    fn enter_char(&mut self, new_char: char) {

        if new_char.is_whitespace() || !new_char.is_ascii_alphanumeric() {
            return;
        }

        let index = self.byte_index();
        self.input.insert(index, new_char);
        self.move_cursor_right();
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can be contain multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.character_index)
            .unwrap_or(self.input.len())
    }

    fn delete_char(&mut self) {
        let is_not_cursor_leftmost = self.character_index != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.character_index;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left();
        }
    }

    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.input.chars().count())
    }

    fn reset_cursor(&mut self) {
        self.character_index = 0;
    }


    async fn submit_message(&mut self) {
        // self.messages.push(self.input.clone());
        match self.state {
            AppState::Register => {

                if self.input.is_empty() {
                    self.error = Some(TuiError::EmptyUsernameInput); // User can't be empty
                    return;
                }

                self.client.set_username(self.input.clone());
                match self.client.register_user().await {
                    Ok(_) => {
                        self.state = AppState::Chats;
                    },
                    Err(e) => {
                        self.error = Some(TuiError::from(e));
                    }
                }
            },
            AppState::Chats => {
                //TODO
            },
            _ => {}
        }
        self.input.clear();
        self.reset_cursor();
    }

    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> AppResult<()> {

        // Main app loop
        while self.running {

            terminal.draw(|frame| self.draw(frame))?;

            if let Event::Key(key) = event::read()? {
                match self.input_mode {

                    InputMode::Normal if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Char('i') => {
                            self.input_mode = InputMode::Insert;
                        }
                        KeyCode::Char('q') => {
                            self.quit();
                        }
                        _ => {}
                    },

                    InputMode::Insert if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Char(to_insert) => self.enter_char(to_insert),
                        KeyCode::Enter => self.submit_message().await,
                        KeyCode::Backspace => self.delete_char(),
                        KeyCode::Left => self.move_cursor_left(),
                        KeyCode::Right => self.move_cursor_right(),
                        KeyCode::Esc => self.input_mode = InputMode::Normal,
                        _ => {}
                    },

                    _ => {}
                }
            }
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
                //TODO
            },
        }
    }

    pub fn quit(&mut self) {
        self.running = false;
    }
}