use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Color, Line, Span, Style, Widget};
use ratatui::widgets::{Block, Borders, Paragraph};
use crate::app::InputMode;

pub(crate) struct PopupWidget {
    input: String,

    character_index: usize,
    input_mode: InputMode,
    display_message: String,
}

impl PopupWidget {
    pub(crate) fn new(input: String, character_index: usize, input_mode: InputMode, display_message: String) -> Self {
        Self {
            input,
            character_index,
            input_mode,
            display_message,
        }
    }
}

impl Widget for PopupWidget {
    fn render(self, area: Rect, buf: &mut Buffer)
    {
            // Create a layout for the popup and its bottom separator
            let popup_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints(vec![
                    Constraint::Length(3),  // Popup takes most of the space
                    Constraint::Length(1), // Space for the horizontal line
                ])
                .split(area);

            // Text input with cursor
            let (before_cursor, after_cursor) = self.input.split_at(self.character_index);
            let input_with_cursor = Line::from(vec![
                Span::raw(before_cursor),
                Span::styled("|", Style::default().fg(Color::Gray)),
                Span::raw(after_cursor),
            ]);

            let input_paragraph = Paragraph::new(input_with_cursor)
                .block(Block::default().borders(Borders::ALL).title(" Add a friend "));

            // Render popup
            input_paragraph.render(popup_layout[0], buf);

            // Render the horizontal line just below the popup
            let line = Paragraph::new(self.display_message)
                .style(Style::default().fg(Color::LightRed));

            line.render(popup_layout[1], buf);
    }
}