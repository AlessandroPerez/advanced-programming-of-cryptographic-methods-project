use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Modifier},
    text::{Text, Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
    buffer::Buffer,
};

use crate::app::InputMode;

pub(crate) struct RegistrationWidget {
    input: String,
    display_message: String,
    character_index: usize,
    input_mode: InputMode,
}

impl RegistrationWidget {
    pub fn new(input: String, display_message: String, character_index: usize, input_mode: InputMode) -> Self {
        Self {
            input,
            display_message,
            character_index,
            input_mode
        }
    }
}

impl Widget for RegistrationWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Define layout constraints
        let input_height = 3;
        let instruction_height = 1;
        let bottom_bar_height = 1; // Bottom bar space

        let vertical_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Min(0),
                    Constraint::Length(input_height),
                    Constraint::Length(instruction_height),
                    Constraint::Min(0),
                    Constraint::Length(bottom_bar_height), // Bottom bar
                ]
                    .as_ref(),
            )
            .split(area);

        // Input field
        let input_area = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(20), Constraint::Percentage(60), Constraint::Percentage(20)])
            .split(vertical_layout[1])[1];

        let (before_cursor, after_cursor) = self.input.split_at(self.character_index);
        let input_with_cursor = Line::from(vec![
            Span::raw(before_cursor),
            Span::styled("|", Style::default().fg(Color::Gray)),
            Span::raw(after_cursor),
        ]);

        let input_paragraph = Paragraph::new(input_with_cursor)
            .block(Block::default().borders(Borders::ALL).title("Username"));
        input_paragraph.render(input_area, buf);

        // Instruction message
        let instruction_area = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(20), Constraint::Percentage(60), Constraint::Percentage(20)])
            .split(vertical_layout[2])[1];

        let instruction_paragraph = Paragraph::new(Line::from(self.display_message))
            .style(Style::default().fg(Color::LightRed));
        instruction_paragraph.render(instruction_area, buf);

        // Bottom bar with background color
        let bottom_bar_area = vertical_layout[4];

        let bottom_text = match self.input_mode {
            InputMode::Normal => Line::from(vec![
                Span::styled(" NORMAL ", Style::default().fg(Color::Black).bg(Color::Rgb(130, 170, 255))),
                Span::styled(" | Press 'i' to enter INSERT mode or 'q' to quit", Style::default().fg(Color::White)),
            ]),

            InputMode::Insert => Line::from(vec![
                Span::styled(" INSERT ", Style::default().fg(Color::Black).bg(Color::Rgb(195, 232, 141))),
                Span::styled(" | Press 'ESC' to enter NORMAL mode", Style::default().fg(Color::White)),
            ])
        };


        let bottom_paragraph = Paragraph::new(bottom_text)
            .block(Block::default().style(Style::default())); // Background color

        bottom_paragraph.render(bottom_bar_area, buf);
    }
}
