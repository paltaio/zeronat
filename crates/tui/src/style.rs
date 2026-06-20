//! Minimal ANSI styling: a small named palette and a width-aware line builder.
//!
//! Lines are built as a list of styled segments, then flattened to a single
//! string padded or truncated to an exact column count. The renderer compares
//! those strings to decide which rows changed, so a stable string for unchanged
//! content is what keeps the screen from flickering.

/// A named foreground colour. Bright 16-colour codes keep the escape sequences
/// short and render the same across terminals without a truecolour assumption.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Default,
    Accent,
    Good,
    Warn,
    Bad,
    Muted,
    Magenta,
}

impl Color {
    fn code(self) -> Option<u8> {
        match self {
            Color::Default => None,
            Color::Accent => Some(96),
            Color::Good => Some(92),
            Color::Warn => Some(93),
            Color::Bad => Some(91),
            Color::Muted => Some(90),
            Color::Magenta => Some(95),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Style {
    pub fg: Color,
    pub bold: bool,
    pub reverse: bool,
}

impl Style {
    pub const fn fg(fg: Color) -> Style {
        Style {
            fg,
            bold: false,
            reverse: false,
        }
    }

    pub const fn bold(mut self) -> Style {
        self.bold = true;
        self
    }

    pub const fn reverse(mut self) -> Style {
        self.reverse = true;
        self
    }

    fn is_plain(self) -> bool {
        self == Style::default()
    }

    /// SGR prefix for this style, or empty when nothing needs setting.
    fn sgr(self) -> String {
        if self.is_plain() {
            return String::new();
        }
        let mut codes: Vec<u8> = Vec::new();
        if self.bold {
            codes.push(1);
        }
        if self.reverse {
            codes.push(7);
        }
        if let Some(c) = self.fg.code() {
            codes.push(c);
        }
        let mut s = String::from("\x1b[");
        for (i, c) in codes.iter().enumerate() {
            if i > 0 {
                s.push(';');
            }
            s.push_str(&c.to_string());
        }
        s.push('m');
        s
    }
}

/// Common styles, named so the screen code reads as intent rather than codes.
pub const PLAIN: Style = Style::fg(Color::Default);
pub const ACCENT: Style = Style::fg(Color::Accent).bold();
pub const MUTED: Style = Style::fg(Color::Muted);
pub const GOOD: Style = Style::fg(Color::Good);
pub const WARN: Style = Style::fg(Color::Warn);
pub const BAD: Style = Style::fg(Color::Bad);

/// A single terminal row under construction: styled segments plus a running
/// visible width so it can be padded or cut to the terminal column count.
#[derive(Default)]
pub struct Line {
    segs: Vec<(Style, String)>,
    width: usize,
}

impl Line {
    pub fn new() -> Line {
        Line::default()
    }

    /// Append `text` in `style`. Returns `&mut self` for call chaining.
    pub fn add(&mut self, style: Style, text: &str) -> &mut Line {
        self.width += text.chars().count();
        self.segs.push((style, text.to_string()));
        self
    }

    /// Append all segments of `other` to this line.
    pub fn append(&mut self, other: &Line) -> &mut Line {
        for (style, text) in &other.segs {
            self.segs.push((*style, text.clone()));
        }
        self.width += other.width;
        self
    }

    /// Pad with plain spaces until the visible width reaches `target` (no-op if
    /// already at or past it).
    pub fn pad_to(&mut self, target: usize) -> &mut Line {
        if self.width < target {
            let n = target - self.width;
            self.add(PLAIN, &" ".repeat(n));
        }
        self
    }

    /// Drop or cut segments so the visible width is at most `max`. Cutting falls
    /// on a char boundary; segment styling is preserved up to the cut.
    pub fn truncate_to(&mut self, max: usize) -> &mut Line {
        if self.width <= max {
            return self;
        }
        let mut acc = 0;
        let mut kept: Vec<(Style, String)> = Vec::new();
        for (style, text) in &self.segs {
            if acc >= max {
                break;
            }
            let chars: Vec<char> = text.chars().collect();
            let avail = max - acc;
            if chars.len() <= avail {
                acc += chars.len();
                kept.push((*style, text.clone()));
            } else {
                kept.push((*style, chars[..avail].iter().collect()));
                acc = max;
                break;
            }
        }
        self.segs = kept;
        self.width = acc;
        self
    }

    pub fn visible_width(&self) -> usize {
        self.width
    }

    /// Flatten to one row exactly `total` columns wide: segments are emitted in
    /// order, each reset after itself so styles never bleed, the row truncated
    /// if it overruns and space-padded if it falls short.
    pub fn fill(&self, total: usize) -> String {
        let mut out = String::new();
        let mut used = 0usize;
        for (style, text) in &self.segs {
            if used >= total {
                break;
            }
            let avail = total - used;
            let chars: Vec<char> = text.chars().collect();
            let take = chars.len().min(avail);
            let slice: String = chars[..take].iter().collect();
            used += take;
            let prefix = style.sgr();
            out.push_str(&prefix);
            out.push_str(&slice);
            if !prefix.is_empty() {
                out.push_str("\x1b[0m");
            }
        }
        if used < total {
            out.push_str(&" ".repeat(total - used));
        }
        out
    }
}
