use std::error;
use tokio::sync::RwLock;
use std::sync::Arc;
use crossterm::event;
use ratatui::{DefaultTerminal, Frame};
use ratatui::backend::Backend;
use client::{ChatMessage, Client};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::widgets::Clear;
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
    pub(crate) active_chat: usize,
    pub(crate) show_popup: bool,
    chat_listener: Option<tokio::task::JoinHandle<()>>,
    pub(crate) incoming_messages: Arc<RwLock<Vec<ChatMessage>>>,


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

    pub(crate) fn new(client: Client, mut chat_rx: tokio::sync::mpsc::Receiver<ChatMessage>) -> Self {
        let mut app = Self {
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
            chat_listener: None,
            incoming_messages: Arc::new(RwLock::new(Vec::new())),
        };

        let incoming_messages = app.incoming_messages.clone();
        app.chat_listener = Some(tokio::spawn(task_receiver(incoming_messages, chat_rx)));
        app

    }


    pub async fn tick(&mut self) {
        let messages = self.incoming_messages.write().await.drain(..).collect::<Vec<ChatMessage>>();
        for message in messages {
            self.handle_incoming_chat_message(message).await;
        }
    }



    pub async fn quit(&mut self) {
        self.running = false;
        self.client.disconnect().await;
        let listener = self.chat_listener.take().unwrap();
        listener.abort();
    }


}



async fn task_receiver(incoming_messages: Arc<RwLock<Vec<ChatMessage>>>, mut chat_rx: tokio::sync::mpsc::Receiver<ChatMessage>){
    while let Some(msg) = chat_rx.recv().await {
        incoming_messages.write().await.push(msg);
    }
}

