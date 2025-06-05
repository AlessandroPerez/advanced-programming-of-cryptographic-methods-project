use client::ChatMessage;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
    buffer::Buffer,
};
use ratatui::layout::{Alignment, Margin};
use ratatui::widgets::{List, ListItem};
use crate::app::InputMode;

pub(crate) struct ChatsWidget {
    whoami: String,
    input: String,
    character_index: usize,
    input_mode: InputMode,
    active_chat: String,
    chats: Vec<String>,
    selected_chat: usize,
    active_window: usize,
    message_history: Option<Vec<ChatMessage>>,
}

impl ChatsWidget {
    pub fn new(
        whoami: String,
        input: String,
        character_index: usize,
        input_mode: InputMode,
        active_chat: String,
        chats: Vec<String>,
        selected_chat: usize,
        active_window: usize,
        message_history: Option<Vec<ChatMessage>>,
    ) -> Self {
        Self {
            whoami,
            input,
            character_index,
            input_mode,
            active_chat,
            chats,
            selected_chat,
            active_window,
            message_history
        }
    }
}

impl Widget for ChatsWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {

        let pippo = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Percentage(99),
                Constraint::Length(1),
            ])
            .split(area);

        let main_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![
                Constraint::Percentage(25),
                Constraint::Percentage(75),
            ])
            .split(pippo[0]);

        let left = Block::default()
            .borders(Borders::ALL)
            .title(" Chats ")
            .title_alignment(Alignment::Center)
            .border_style(Style::default().fg(
                if self.active_window == 0 {
                        Color::Rgb(156,207, 216)
                    } else {
                        Color::Rgb(49, 116, 143)
                    }
                )
                .add_modifier(
                    if self.active_window == 0 {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }
                )
            );

        left.render(main_layout[0], buf);

        let chat_area = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),      // The messages area grows as much as possible
                Constraint::Length(3),   // The input area has a fixed height
            ])
            .split(main_layout[1]);

        let messages = self.message_history.unwrap_or(vec![])
            .iter()
            .map(|msg| {
                let style = if msg.from == self.whoami {
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::Rgb(224, 222, 244))
                } else {
                    Style::default().fg(Color::Rgb(144, 140, 170))
                };

                ListItem::new(format!("> {}", msg.text))
                    .style(style)
            })
            .collect::<Vec<_>>();

        let right = List::new(messages).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", self.active_chat))
                .title_alignment(Alignment::Center)
                .border_style(Style::default().fg(
                        if self.active_window == 1 {
                        Color::Rgb(156,207, 216)
                    } else {
                        Color::Rgb(49, 116, 143)
                    }
                ).add_modifier(
                    if self.active_window == 1 {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }
                )
            )
        );

        right.render(chat_area[0], buf);

        let byte_index = self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.character_index)
            .unwrap_or_else(|| self.input.len());

        let (before_cursor, after_cursor) = self.input.split_at(byte_index);
        let input_with_cursor = Line::from(vec![
            Span::raw(before_cursor),
            Span::styled("|", Style::default().fg(Color::Gray)),
            Span::raw(after_cursor),
        ]);

        let input_paragraph = Paragraph::new(input_with_cursor)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Input")
                    .border_style(Style::default().fg(
                        if self.active_window == 1 {
                            Color::Rgb(156,207, 216)
                        } else {
                            Color::Rgb(49, 116, 143)
                        }
                    ).add_modifier(
                        if self.active_window == 1 {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }
                    )
                )
            );
        input_paragraph.render(chat_area[1], buf);

        let inner_chats_area = main_layout[0].inner(Margin { vertical: 1, horizontal: 1 });

        
        let chats_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                self.chats.iter().map(|_| Constraint::Length(3)).collect::<Vec<_>>()
            )
            .split(inner_chats_area);

        for (i, chat) in self.chats.iter().enumerate() {
            let (text_style, border_style) = if i == self.selected_chat && self.active_window == 0 {
                (
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::Rgb(156, 207, 216)),
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::Rgb(156, 207, 216))
                )
            } else {
                (
                    Style::default().fg(Color::Rgb(49, 116, 143)),
                    Style::default().fg(Color::Rgb(49, 116, 143))
                )
            };

            let chat_rows_layout = Paragraph::new(Span::styled(
                chat.clone(),
                text_style,
            ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style),
                );

            chat_rows_layout.render(chats_layout[i], buf);
        }

        let bottom_text = match self.input_mode {
            InputMode::Normal => Line::from(vec![
                Span::styled(" NORMAL ", Style::default().fg(Color::Black).bg(Color::Rgb(196, 167, 231))),
                Span::styled(" | Press 'a' to add a friend, 'i' to enter INSERT mode, 'q' to quit", Style::default().fg(Color::White)),
            ]),

            InputMode::Insert => Line::from(vec![
                Span::styled(" INSERT ", Style::default().fg(Color::Black).bg(Color::Rgb(246, 193, 119))),
                Span::styled(" | Press 'ESC' to enter NORMAL mode", Style::default().fg(Color::White)),
            ])
        };

        let bottom_paragraph = Paragraph::new(bottom_text)
            .block(Block::default().style(Style::default())); // Background color

        bottom_paragraph.render(pippo[1], buf);
    }

}