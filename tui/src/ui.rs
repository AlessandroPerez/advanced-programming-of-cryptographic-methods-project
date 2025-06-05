use ratatui::{
    layout::Alignment,
    style::{Color, Style},
    widgets::Paragraph,
    Frame,
};
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::widgets::Clear;
use crate::app::{App, AppState};
use crate::widgets::chats::ChatsWidget;
use crate::widgets::popup::PopupWidget;
use crate::widgets::register::RegistrationWidget;
use crate::widgets::empty_page::EmptyPage;

/// Renders the user interface widgets.
pub fn render(app: &mut App, frame: &mut Frame) {

    frame.render_widget(ratatui::widgets::Block::default().style(Style::default().bg(Color::Rgb(31, 29, 46))), frame.area());

    match app.state {
        AppState::Register => {
            let mut error_message = String::new();
            if let Some(error) = &app.error {
                error_message = error.to_string();
            }
            frame.render_widget(
                RegistrationWidget::new(
                    app.input.clone(), // Input
                    error_message, // Error message
                    app.character_index, // Cursor position
                    app.input_mode.clone(), // Current input mode
                ),
                frame.area()
            );

        },
        AppState::Chats => {
            let chats = app.client.get_open_chats();

            if chats.is_empty() {

                frame.render_widget(Clear, frame.area()); //this clears out the background
                frame.render_widget(ratatui::widgets::Block::default().style(Style::default().bg(Color::Rgb(31, 29, 46))), frame.area());
                frame.render_widget(EmptyPage::new(app.input_mode.clone()), frame.area());

            }else {
                let active_chat_history = app.client.get_chat_history(&chats[app.active_chat]);
                frame.render_widget(
                    ChatsWidget::new(
                        app.client.username.clone(),
                        if app.show_popup {String::new()} else { app.input.clone() },
                        app.character_index,
                        app.input_mode.clone(),
                        chats[app.active_chat].clone(),
                        chats,
                        app.selected_chat,
                        app.active_window,
                        active_chat_history,
                    ),
                    frame.area()
                );
            }
            let area = frame.area();
            if app.show_popup {
                let error_message = match &app.error {
                    Some(e) => e.to_string(),
                    None => String::new(),
                };
                let area = popup_area(area, 30, 4);
                frame.render_widget(Clear, area); //this clears out the background
                frame.render_widget(ratatui::widgets::Block::default().style(Style::default().bg(Color::Rgb(31, 29, 46))), area);
                frame.render_widget(PopupWidget::new(
                    app.input.clone(),
                    app.character_index,
                    app.input_mode.clone(),
                    error_message,
                ), area);
            }
        },
    }
}
fn popup_area(area: Rect, len_x: u16, len_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(len_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Length(len_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}