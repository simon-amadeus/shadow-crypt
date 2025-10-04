//! Modern grid layout system for terminal text display
//! 
//! This module provides a clean, flexible grid layout system optimized for terminal
//! output with proper column alignment and modern color management.

use colored::*;

/// Column alignment options
#[derive(Debug, Clone, Copy)]
pub enum Alignment {
    Left,
    Right,
    Center,
}

/// Column configuration for the grid
#[derive(Debug, Clone)]
pub struct ColumnConfig {
    pub header: String,
    pub width: usize,
    pub alignment: Alignment,
    pub color: Option<Color>,
}

impl ColumnConfig {
    /// Create a new column configuration
    pub fn new(header: &str, width: usize, alignment: Alignment) -> Self {
        Self {
            header: header.to_string(),
            width,
            alignment,
            color: None,
        }
    }
    
    /// Set the color for this column
    pub fn with_color(mut self, color: Color) -> Self {
        self.color = Some(color);
        self
    }
}

/// A row of data in the grid
#[derive(Debug, Clone)]
pub struct GridRow {
    pub cells: Vec<String>,
    pub colors: Vec<Option<Color>>,
}

impl GridRow {
    /// Create a new row with the given cells
    pub fn new(cells: Vec<String>) -> Self {
        let colors = vec![None; cells.len()];
        Self { cells, colors }
    }
    
    /// Set color for a specific cell
    pub fn with_cell_color(mut self, index: usize, color: Color) -> Self {
        if index < self.colors.len() {
            self.colors[index] = Some(color);
        }
        self
    }
}

/// Modern terminal grid layout system
pub struct TerminalGrid {
    columns: Vec<ColumnConfig>,
    rows: Vec<GridRow>,
    use_colors: bool,
}

impl TerminalGrid {
    /// Create a new terminal grid with column configurations
    pub fn new(columns: Vec<ColumnConfig>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            use_colors: Self::should_use_colors(),
        }
    }
    
    /// Create a grid without colors for compatibility
    pub fn without_colors(columns: Vec<ColumnConfig>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            use_colors: false,
        }
    }
    
    /// Check if colors should be used
    fn should_use_colors() -> bool {
        colored::control::SHOULD_COLORIZE.should_colorize()
    }
    
    /// Add a row to the grid
    pub fn add_row(&mut self, row: GridRow) {
        self.rows.push(row);
    }
    
    /// Format and render the entire grid
    pub fn render(&self) -> String {
        let mut output = String::new();
        
        // Render headers
        output.push_str(&self.render_headers());
        output.push('\n');
        
        // Render separator
        output.push_str(&self.render_separator());
        output.push('\n');
        
        // Render data rows
        for row in &self.rows {
            output.push_str(&self.render_row(row));
            output.push('\n');
        }
        
        output
    }
    
    /// Render the header row
    fn render_headers(&self) -> String {
        let mut formatted_headers = Vec::new();
        
        for column in &self.columns {
            let header = self.truncate_text(&column.header, column.width);
            let aligned = self.align_text(&header, column.width, column.alignment);
            
            let colored_header = if self.use_colors {
                aligned.bold().color(Color::Blue).to_string()
            } else {
                aligned
            };
            
            formatted_headers.push(colored_header);
        }
        
        formatted_headers.join(" ")
    }
    
    /// Render a separator line
    fn render_separator(&self) -> String {
        let total_width: usize = self.columns.iter().map(|c| c.width).sum::<usize>() 
            + (self.columns.len().saturating_sub(1)); // Space between columns
        
        let separator = "─".repeat(total_width);
        
        if self.use_colors {
            separator.color(Color::Blue).dimmed().to_string()
        } else {
            separator
        }
    }
    
    /// Render a data row
    fn render_row(&self, row: &GridRow) -> String {
        let mut formatted_cells = Vec::new();
        
        for (i, column) in self.columns.iter().enumerate() {
            let cell_text = row.cells.get(i).map(|s| s.as_str()).unwrap_or("");
            let truncated = self.truncate_text(cell_text, column.width);
            let aligned = self.align_text(&truncated, column.width, column.alignment);
            
            let colored_cell = if self.use_colors {
                let color = row.colors.get(i).and_then(|c| *c)
                    .or(column.color)
                    .unwrap_or(Color::White);
                aligned.color(color).to_string()
            } else {
                aligned
            };
            
            formatted_cells.push(colored_cell);
        }
        
        formatted_cells.join(" ")
    }
    
    /// Truncate text to fit within specified width
    fn truncate_text(&self, text: &str, max_width: usize) -> String {
        if text.chars().count() <= max_width {
            text.to_string()
        } else {
            let truncated: String = text.chars().take(max_width.saturating_sub(3)).collect();
            format!("{}...", truncated)
        }
    }
    
    /// Align text within the specified width
    fn align_text(&self, text: &str, width: usize, alignment: Alignment) -> String {
        let text_len = text.chars().count();
        if text_len >= width {
            return text.to_string();
        }
        
        let padding = width - text_len;
        
        match alignment {
            Alignment::Left => format!("{}{}", text, " ".repeat(padding)),
            Alignment::Right => format!("{}{}", " ".repeat(padding), text),
            Alignment::Center => {
                let left_pad = padding / 2;
                let right_pad = padding - left_pad;
                format!("{}{}{}", " ".repeat(left_pad), text, " ".repeat(right_pad))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_column_config_creation() {
        let config = ColumnConfig::new("TEST", 10, Alignment::Left);
        assert_eq!(config.header, "TEST");
        assert_eq!(config.width, 10);
        assert!(matches!(config.alignment, Alignment::Left));
        assert!(config.color.is_none());
        
        let config_with_color = config.with_color(Color::Red);
        assert_eq!(config_with_color.color, Some(Color::Red));
    }
    
    #[test]
    fn test_grid_row_creation() {
        let row = GridRow::new(vec!["cell1".to_string(), "cell2".to_string()]);
        assert_eq!(row.cells.len(), 2);
        assert_eq!(row.colors.len(), 2);
        assert!(row.colors.iter().all(|c| c.is_none()));
        
        let colored_row = row.with_cell_color(0, Color::Green);
        assert_eq!(colored_row.colors[0], Some(Color::Green));
    }
    
    #[test]
    fn test_text_truncation() {
        let columns = vec![ColumnConfig::new("Test", 10, Alignment::Left)];
        let grid = TerminalGrid::without_colors(columns);
        
        assert_eq!(grid.truncate_text("short", 10), "short");
        assert_eq!(grid.truncate_text("this is a very long text", 10), "this is...");
    }
    
    #[test]
    fn test_text_alignment() {
        let columns = vec![ColumnConfig::new("Test", 10, Alignment::Left)];
        let grid = TerminalGrid::without_colors(columns);
        
        assert_eq!(grid.align_text("test", 10, Alignment::Left), "test      ");
        assert_eq!(grid.align_text("test", 10, Alignment::Right), "      test");
        assert_eq!(grid.align_text("test", 10, Alignment::Center), "   test   ");
    }
    
    #[test]
    fn test_grid_rendering() {
        let columns = vec![
            ColumnConfig::new("COL1", 8, Alignment::Left),
            ColumnConfig::new("COL2", 8, Alignment::Right),
        ];
        let mut grid = TerminalGrid::without_colors(columns);
        
        grid.add_row(GridRow::new(vec!["data1".to_string(), "data2".to_string()]));
        
        let output = grid.render();
        assert!(output.contains("COL1"));
        assert!(output.contains("COL2"));
        assert!(output.contains("data1"));
        assert!(output.contains("data2"));
        assert!(output.contains("─")); // Separator
    }
}