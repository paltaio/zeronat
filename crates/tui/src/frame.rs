//! Box-drawing helpers. Every function returns a finished row string of exactly
//! `width` columns, so a screen is just a `Vec<String>` the renderer can diff.

use crate::style::{Line, ACCENT, MUTED, PLAIN};

/// Top border carrying a left title group and a right status group, joined by a
/// run of dashes: `┌─ left ──────── right ─┐`. The groups are trimmed to fit so
/// the `─┐` corner always survives a narrow terminal or long titles.
pub fn top(width: usize, mut left: Line, mut right: Line) -> String {
    // Fixed cells: "┌─ " (3) + " " + " " + " ─┐" (3), plus one dash minimum.
    let fixed = 8;
    let budget = width.saturating_sub(fixed + 1);
    right.truncate_to(budget / 2);
    left.truncate_to(budget.saturating_sub(right.visible_width()));
    let tw = left.visible_width();
    let rw = right.visible_width();
    let fill = width.saturating_sub(fixed + tw + rw).max(1);

    let mut l = Line::new();
    l.add(MUTED, "┌─ ");
    l.append(&left);
    l.add(MUTED, " ");
    l.add(MUTED, &"─".repeat(fill));
    l.add(MUTED, " ");
    l.append(&right);
    l.add(MUTED, " ─┐");
    l.fill(width)
}

/// A content row inside the frame: `│ <content padded> │`. Content is trimmed to
/// the inner width first so the closing `│` is never pushed off the row.
pub fn row(width: usize, mut content: Line) -> String {
    content.truncate_to(width.saturating_sub(4));
    let mut l = Line::new();
    l.add(MUTED, "│ ");
    l.append(&content);
    l.pad_to(width.saturating_sub(2));
    l.add(MUTED, " │");
    l.fill(width)
}

/// A content row with the content horizontally centred. Used by modal panels.
pub fn row_center(width: usize, content: Line) -> String {
    let inner = width.saturating_sub(4);
    let cw = content.visible_width().min(inner);
    let left_pad = (inner - cw) / 2;
    let mut padded = Line::new();
    padded.add(PLAIN, &" ".repeat(left_pad));
    padded.append(&content);
    row(width, padded)
}

pub fn blank(width: usize) -> String {
    row(width, Line::new())
}

/// A `├────┤` divider between sections.
pub fn divider(width: usize) -> String {
    let mut l = Line::new();
    l.add(MUTED, "├");
    l.add(MUTED, &"─".repeat(width.saturating_sub(2)));
    l.add(MUTED, "┤");
    l.fill(width)
}

/// The closing `└────┘` border.
pub fn bottom(width: usize) -> String {
    let mut l = Line::new();
    l.add(MUTED, "└");
    l.add(MUTED, &"─".repeat(width.saturating_sub(2)));
    l.add(MUTED, "┘");
    l.fill(width)
}

/// A title row for a modal panel: an accent caption with a dashed fill.
pub fn panel_title(width: usize, caption: &str) -> String {
    let mut l = Line::new();
    l.add(ACCENT, caption);
    l.add(MUTED, "  ");
    let used = caption.chars().count() + 2;
    let inner = width.saturating_sub(4);
    l.add(MUTED, &"─".repeat(inner.saturating_sub(used)));
    row(width, l)
}

/// Overwrite `base` rows starting at `top_row` with `panel` rows. Used to lay a
/// modal over the live screen without rebuilding the part underneath.
pub fn overlay(base: &mut [String], panel: &[String], top_row: usize) {
    for (i, p) in panel.iter().enumerate() {
        let idx = top_row + i;
        if idx < base.len() {
            base[idx] = p.clone();
        }
    }
}
