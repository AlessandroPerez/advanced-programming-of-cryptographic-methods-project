use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
    buffer::Buffer,
};

use ratatui::layout::{Alignment};
use crate::app::InputMode;
use ratatui::widgets::block::Padding;

pub(crate) struct EmptyPage {
    input_mode: InputMode,
}

impl EmptyPage {
    pub fn new(input_mode: InputMode) -> Self {
        Self {
            input_mode
        }
    }
}

impl Widget for EmptyPage {
    fn render(self, area: Rect, buf: &mut Buffer) {

        let vertical_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Min(0),
                Constraint::Length(3),
            ])
            .split(area);


        let title_text = Paragraph::new("No chats available")
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .style(Style::default())
                    .title("")  // No title needed here
                    .borders(Borders::NONE)
                    .padding(Padding::new(0, 0, vertical_layout[0].height / 2 - 1, 0)), // Top padding to vertically center
            );

        title_text.render(vertical_layout[0], buf);

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

        bottom_paragraph.render(vertical_layout[1], buf);

    }
}