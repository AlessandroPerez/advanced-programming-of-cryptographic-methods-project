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
                        Color::LightGreen
                    } else {
                        Color::White
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
                ListItem::new(format!("{}: {}", msg.from, msg.text))
                    .style(Style::default().fg(Color::White))
            })
            .collect::<Vec<_>>();

        let right = List::new(messages).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", self.active_chat))
                .title_alignment(Alignment::Center)
                .border_style(Style::default().fg(
                        if self.active_window == 1 {
                        Color::LightGreen
                    } else {
                        Color::White
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

        let (before_cursor, after_cursor) = self.input.split_at(self.character_index);
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
                    .style(Style::default().fg(
                        if self.active_window == 1 {
                            Color::LightGreen
                        } else {
                            Color::White
                        }
                    ))
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
            let chat_rows_layout = Paragraph::new(Span::styled(
                chat.clone(),
                Style::default().add_modifier(
                    if i == self.selected_chat {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }
                ),
            ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().add_modifier(
                            if i == self.selected_chat {
                                Modifier::BOLD
                            } else {
                                Modifier::empty()
                            }
                        )),
                );

            chat_rows_layout.render(chats_layout[i], buf);
        }

        let bottom_text = match self.input_mode {
            InputMode::Normal => Line::from(vec![
                Span::styled(" NORMAL ", Style::default().fg(Color::Black).bg(Color::Rgb(130, 170, 255))),
                Span::styled(" | Press 'a' to add a friend, 'i' to enter INSERT mode, 'q' to quit", Style::default().fg(Color::White)),
            ]),

            InputMode::Insert => Line::from(vec![
                Span::styled(" INSERT ", Style::default().fg(Color::Black).bg(Color::Rgb(195, 232, 141))),
                Span::styled(" | Press 'ESC' to enter NORMAL mode", Style::default().fg(Color::White)),
            ])
        };

        let bottom_paragraph = Paragraph::new(bottom_text)
            .block(Block::default().style(Style::default())); // Background color

        bottom_paragraph.render(pippo[1], buf);
    }

    // fn render(self, area: Rect, buf: &mut Buffer) {
    //     // Define the main bordered area excluding the bottom bar
    //     let border_block = Block::default()
    //         .borders(Borders::ALL)
    //         .border_style(Style::default().fg(Color::White));
    //
    //     let inner_area = border_block.inner(area);
    //
    //     // Split the bordered area into two panels: left (list) and right (chat)
    //     let horizontal_layout = Layout::default()
    //         .direction(Direction::Horizontal)
    //         .constraints([Constraint::Percentage(30), Constraint::Min(1), Constraint::Percentage(69)]) // 1% for the separator
    //         .split(inner_area);
    //
    //     let left_panel = horizontal_layout[0]; // List of items
    //     let separator = horizontal_layout[1];  // Separator line
    //     let right_panel = horizontal_layout[2]; // Chat content
    //
    //     // Draw the separator line
    //     for y in separator.y..separator.y + separator.height {
    //         buf.set_string(separator.x, y, "│", Style::default().fg(Color::White));
    //     }
    //
    //     // Left panel title ("Chats")
    //     let left_title = Paragraph::new(" Chats ")
    //         .block(Block::default()
    //             .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
    //             .border_style(Style::default().fg(Color::White))
    //         );
    //     left_title.render(left_panel, buf);
    //
    //     // Right panel title (active chat name)
    //     let right_title = Paragraph::new(format!(" {} ", self.active_chat))
    //         .block(Block::default()
    //             .borders(Borders::TOP | Borders::RIGHT)
    //             .border_style(Style::default().fg(Color::White))
    //         );
    //     right_title.render(right_panel, buf);
    //
    //     // Define layout for the left list items (excluding title)
    //     let list_area = Rect {
    //         x: left_panel.x,
    //         y: left_panel.y + 1,
    //         width: left_panel.width,
    //         height: left_panel.height - 1,
    //     };
    //
    //     let list_layout = Layout::default()
    //         .direction(Direction::Vertical)
    //         .constraints(vec![Constraint::Length(3); self.chats.len()])
    //         .split(list_area);
    //
    //     // Render each chat item
    //     for (i, (rect, item)) in list_layout.iter().zip(self.chats.iter()).enumerate() {
    //         let is_selected = i == self.selected_chat;
    //
    //         let item_style = if is_selected {
    //             Style::default()
    //                 .fg(Color::Black)
    //                 .bg(Color::White)
    //                 .add_modifier(Modifier::BOLD)
    //         } else {
    //             Style::default().fg(Color::White) // Transparent background
    //         };
    //
    //         let block = Block::default()
    //             .borders(Borders::ALL)
    //             .border_style(if is_selected {
    //                 Style::default().fg(Color::Black)
    //             } else {
    //                 Style::default().fg(Color::White)
    //             });
    //
    //         let paragraph = Paragraph::new(Line::from(Span::styled(item.clone(), item_style))).block(block);
    //         paragraph.render(*rect, buf);
    //     }
    //
    //     // Define layout constraints inside the right panel
    //     let input_height = 3;
    //     let instruction_height = 1;
    //
    //     let vertical_layout = Layout::default()
    //         .direction(Direction::Vertical)
    //         .constraints(
    //             [
    //                 Constraint::Min(0),
    //                 Constraint::Length(instruction_height),
    //                 Constraint::Length(input_height),
    //             ]
    //                 .as_ref(),
    //         )
    //         .split(right_panel);
    //
    //     // Input field at the bottom of the right panel
    //     let input_area = Layout::default()
    //         .direction(Direction::Horizontal)
    //         .constraints([Constraint::Percentage(20), Constraint::Percentage(60), Constraint::Percentage(20)])
    //         .split(vertical_layout[2])[1];
    //
    //     let (before_cursor, after_cursor) = self.input.split_at(self.character_index);
    //     let input_with_cursor = Line::from(vec![
    //         Span::raw(before_cursor),
    //         Span::styled("|", Style::default().fg(Color::Gray)),
    //         Span::raw(after_cursor),
    //     ]);
    //
    //     let input_paragraph = Paragraph::new(input_with_cursor)
    //         .block(Block::default().borders(Borders::ALL).title(""));
    //     input_paragraph.render(input_area, buf);
    //
    //     // Render the white border
    //     border_block.render(area, buf);
    //
    //     // Bottom bar (outside the white border)
    //     let bottom_bar_area = Rect {
    //         x: area.x,
    //         y: area.y + area.height.saturating_sub(1),
    //         width: area.width,
    //         height: 1,
    //     };
    //
    //     let bottom_text = match self.input_mode {
    //         InputMode::Normal => Line::from(vec![
    //             Span::styled(" NORMAL ", Style::default().fg(Color::Black).bg(Color::Rgb(130, 170, 255))),
    //             Span::styled(" | Press 'i' to enter INSERT mode or 'q' to quit ", Style::default().fg(Color::White)),
    //         ]),
    //
    //         InputMode::Insert => Line::from(vec![
    //             Span::styled(" INSERT ", Style::default().fg(Color::Black).bg(Color::Rgb(195, 232, 141))),
    //             Span::styled(" | Press 'ESC' to enter NORMAL mode ", Style::default().fg(Color::White)),
    //         ])
    //     };
    //
    //     let bottom_paragraph = Paragraph::new(bottom_text);
    //     bottom_paragraph.render(bottom_bar_area, buf);
    // }

}