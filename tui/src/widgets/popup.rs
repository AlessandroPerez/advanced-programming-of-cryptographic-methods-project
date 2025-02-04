use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::prelude::{Color, Line, Span, Style, Widget};
use ratatui::widgets::{Block, Borders, Paragraph};
use crate::app::InputMode;

pub(crate) struct PopupWidget {
    input: String,

    character_index: usize,
    input_mode: InputMode,
}

impl PopupWidget {
    pub(crate) fn new(input: String, character_index: usize, input_mode: InputMode) -> Self {
        Self {
            input,
            character_index,
            input_mode
        }
    }
}

impl Widget for PopupWidget {
    fn render(self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized
    {

        let (before_cursor, after_cursor) = self.input.split_at(self.character_index);
        let input_with_cursor = Line::from(vec![
            Span::raw(before_cursor),
            Span::styled("|", Style::default().fg(Color::Gray)),
            Span::raw(after_cursor),
        ]);

        let input_paragraph = Paragraph::new(input_with_cursor)
            .block(Block::default().borders(Borders::ALL).title(" Add a friend "));
        input_paragraph.render(area, buf);

    }
}