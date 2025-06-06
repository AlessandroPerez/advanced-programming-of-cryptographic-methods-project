use chrono::{DateTime, Utc};
use client::ChatMessage;
use crate::app::{App, AppResult, AppState, InputMode};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use crate::errors::TuiError;

pub async fn handle_key_events(key: KeyEvent, app: &mut App) -> AppResult<()> {

        match app.input_mode {

            InputMode::Normal if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('i') => {
                    app.input_mode = InputMode::Insert;
                    app.input.clear();
                    app.reset_cursor();
                },
                KeyCode::Char('q') => {
                    if !app.show_popup {
                        app.quit().await;
                    }
                },

                KeyCode::Char('a') | KeyCode::Char('/') if app.state == AppState::Chats => {
                    app.show_popup = !app.show_popup;
                    app.input_mode = InputMode::Insert;
                    app.error = None;
                    app.input.clear();
                    app.reset_cursor();
                },

                KeyCode::Left | KeyCode::Char('h') if app.state == AppState::Chats => {
                    if !app.show_popup {
                        app.active_window = 0;
                    }
                },

                KeyCode::Right | KeyCode::Char('l') if app.state == AppState::Chats => {
                    if !app.show_popup {
                        app.active_window = 1;
                    }
                },

                KeyCode::Down | KeyCode::Char('j') if app.state == AppState::Chats && app.active_window == 0 => {
                    if !app.show_popup {
                        app.selected_chat = (app.selected_chat + 1) % app.client.get_friends_count(); //app.client.friends.len();
                    }

                },

                KeyCode::Up | KeyCode::Char('k') if app.state == AppState::Chats && app.active_window == 0 => {
                    if !app.show_popup {
                        app.selected_chat = (app.selected_chat  + app.client.get_friends_count() - 1) % app.client.get_friends_count(); //app.client.friends.len();
                    }
                },

                KeyCode::Esc if app.state == AppState::Chats && app.show_popup => {
                    app.show_popup = false;
                },

                KeyCode::Enter if app.state == AppState::Chats && !app.show_popup => {
                    app.submit_message().await;

                },

                _ => {}
            },

            InputMode::Insert if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char(to_insert) => {
                    if app.state == AppState::Chats &&
                        !app.show_popup &&
                        app.active_window == 0 {
                        return Ok(());
                    }
                    app.enter_char(to_insert)
                },
                KeyCode::Enter => app.submit_message().await,
                KeyCode::Backspace => app.delete_char(),
                KeyCode::Left => app.move_cursor_left(),
                KeyCode::Right => app.move_cursor_right(),
                KeyCode::Esc => app.input_mode = InputMode::Normal,
                _ => {}
            },

            _ => {}
        }


    Ok(())
}


impl App {
    pub(crate) fn move_cursor_left(&mut self) {
        if self.character_index > 0 {
            // Move one character left safely
            self.character_index -= 1;
        }
        self.character_index = self.clamp_cursor(self.character_index);
    }

    pub(crate) fn move_cursor_right(&mut self) {
        if self.character_index < self.input.chars().count() {
            // Move one character right safely
            self.character_index += 1;
        }
        self.character_index = self.clamp_cursor(self.character_index);
    }

    pub(crate) fn enter_char(&mut self, new_char: char) {
        if self.input_mode == InputMode::Insert {
            match self.state {
                AppState::Register => {
                    if new_char.is_whitespace() || !new_char.is_ascii_alphanumeric() {
                        return; // Disallow whitespace and non-alphanumeric characters in Register state
                    }
                },
                AppState::Chats => {
                    if self.show_popup && (new_char.is_whitespace() || !new_char.is_ascii_alphanumeric()) {
                        return; // Restrict input when popup is shown in Chats state
                    }
                },
            }

            let index = self.byte_index(); // Get byte index corresponding to the cursor position
            self.input.insert(index, new_char); // Insert the new character at the correct byte index
            self.move_cursor_right(); // Move the cursor right after insertion
        }
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can be contained multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.character_index)
            .unwrap_or(self.input.len())
    }

    pub(crate) fn delete_char(&mut self) {
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


    pub(crate) async fn submit_message(&mut self) {
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
                match self.input_mode {
                    InputMode::Normal => {
                        if !self.show_popup {
                            if self.active_window == 0 {
                                self.active_chat = self.selected_chat;
                            }
                        }
                    },
                    InputMode::Insert => {
                        if self.show_popup {

                            if self.input == self.client.username {
                                self.error = Some(TuiError::InvalidUser("Cannot add yourself".to_string()));
                                return;
                            }

                            match self.client.get_user_prekey_bundle(self.input.clone()).await {
                                Ok(_) => {
                                    self.show_popup = false;
                                },
                                Err(e) => {
                                    self.error = Some(TuiError::from(e));
                                }
                            }
                        } else {
                            if self.active_window == 1 && !self.input.is_empty() {

                                let message = ChatMessage::new(
                                    "chat".to_string(), // msg_type
                                    self.client.get_open_chats()[self.active_chat].clone(), // to
                                    self.client.username.clone(), // from
                                    self.input.clone(), // text
                                    DateTime::from(Utc::now()), // timestamp
                                );

                                self.client.send_chat_message(message.clone()).await.expect("Failed to send message");
                                self.client.add_chat_message(message.clone(), &message.to);
                                self.input.clear();
                                self.reset_cursor();
                            }
                        }
                    }
                }
            },
        }
        self.input.clear();
        self.reset_cursor();
    }

    pub(crate) async fn handle_incoming_chat_message(&mut self, message: ChatMessage) {
        match message.msg_type.as_str() {
            "initial_message" => {
                self.client.add_friend(message).expect("Cannot add friend");
            },
            "chat" => {
                self.client.decrypt_chat_message(message).ok();
            },

            "close_chat" => {
                self.client.remove_friend(message.from);
            },
            _ => {}
        }
    }
}