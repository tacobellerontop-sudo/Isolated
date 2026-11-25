//! How windows of sandboxed apps are marked: a colored frame around the
//! active one and a tag in front of their titles. The Windows backend draws
//! them; this module holds the parts that can be tested anywhere.

/// Amber, easy to tell apart from the usual window accent colors.
pub const DEFAULT_FRAME_COLOR: &str = "#F5B400";

/// Every tag starts with this, so an already tagged title is recognized
/// whatever container name follows.
const TAG_START: &str = "[Isolated";

/// The tag for windows of a sandbox: `[Isolated] ` or, inside a container
/// or an isolated folder, `[Isolated: name] `.
pub fn title_tag(label: Option<&str>) -> String {
    match label.map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => {
            let l: String = l.chars().filter(|c| !c.is_control()).take(40).collect();
            format!("[Isolated: {l}] ")
        }
        None => "[Isolated] ".into(),
    }
}

/// The title to set on a window, or `None` when it is empty or already
/// tagged (apps that read their own title back must not get two tags).
pub fn tagged_title(title: &str, tag: &str) -> Option<String> {
    if title.trim().is_empty() || title.starts_with(TAG_START) {
        return None;
    }
    Some(format!("{tag}{title}"))
}

/// Parses `#RRGGBB` (the `#` is optional).
pub fn parse_color(s: &str) -> Option<[u8; 3]> {
    let h = s.trim().trim_start_matches('#');
    if h.len() != 6 || !h.is_ascii() {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

pub fn format_color(c: [u8; 3]) -> String {
    format!("#{:02X}{:02X}{:02X}", c[0], c[1], c[2])
}

/// The frame color from settings, or the default if it can't be read.
pub fn frame_color(setting: &str) -> [u8; 3] {
    parse_color(setting).unwrap_or_else(|| parse_color(DEFAULT_FRAME_COLOR).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_once() {
        let tag = title_tag(None);
        assert_eq!(tagged_title("Notepad", &tag).as_deref(), Some("[Isolated] Notepad"));
        assert_eq!(tagged_title("[Isolated] Notepad", &tag), None);
        assert_eq!(tagged_title("[Isolated: AI] Notepad", &tag), None);
        assert_eq!(tagged_title("", &tag), None);
        assert_eq!(tagged_title("  ", &tag), None);
    }

    #[test]
    fn tag_names_the_container() {
        assert_eq!(title_tag(Some("AI apps")), "[Isolated: AI apps] ");
        assert_eq!(title_tag(Some("  ")), "[Isolated] ");
        assert_eq!(title_tag(Some("a\nb")), "[Isolated: ab] ");
    }

    #[test]
    fn colors() {
        assert_eq!(parse_color("#F5B400"), Some([0xF5, 0xB4, 0x00]));
        assert_eq!(parse_color("00ff00"), Some([0, 255, 0]));
        assert_eq!(parse_color("#FFF"), None);
        assert_eq!(parse_color("#GG0000"), None);
        assert_eq!(format_color([0xF5, 0xB4, 0]), "#F5B400");
        assert_eq!(frame_color("junk"), [0xF5, 0xB4, 0]);
    }
}
