//! Converted documents cut into XHTML-MP pages that each fit one WSP reply.
//!
//! A page carries the document title with its number, a run of blocks and a navigation line
//! (Anterior | Siguiente | Inicio). Links point to the gateway (`/l/doc/k`, `/p/doc/n`), resolved
//! against a `<base>` with the gateway's address. Long paragraphs are cut at the end of a
//! sentence when possible, never inside a link.

use super::convert::{Block, Document, Field, Inline, escape};
use super::home::{DOCTYPE, HTML_OPEN, PROLOG};

/// Pages at least this big carry the XML declaration and the DOCTYPE.
const FULL_MARKUP_BYTES: usize = 900;
/// Below this, the title and the navigation words are shortened.
const COMPACT_MARKUP_BYTES: usize = 450;
/// A paragraph is only cut when at least this much room is left on the page.
const MIN_SPLIT_BYTES: usize = 60;
/// Smallest piece of a paragraph left at the bottom of a page.
const MIN_HEAD_CHARS: usize = 12;
const TITLE_CHARS: usize = 30;
const TRUNCATED_NOTE: &str = "<p>(Documento recortado)</p>";
/// Smallest room for content on a page.
const MIN_CONTENT_BYTES: usize = 24;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Markup {
    Full,
    Compact,
    Tiny,
}

impl Markup {
    fn for_size(page_bytes: usize) -> Self {
        if page_bytes >= FULL_MARKUP_BYTES {
            Markup::Full
        } else if page_bytes >= COMPACT_MARKUP_BYTES {
            Markup::Compact
        } else {
            Markup::Tiny
        }
    }
}

struct Layout<'a> {
    doc: &'a Document,
    id: u32,
    home: &'a str,
    markup: Markup,
}

impl Layout<'_> {
    fn title(&self) -> String {
        let t: String = self.doc.title.chars().take(TITLE_CHARS).collect();
        escape(t.trim())
    }

    /// Everything around the content of page `n` of `total`.
    fn chrome(&self, n: usize, total: usize, truncated: bool) -> (String, String) {
        let (prolog, doctype) = if self.markup == Markup::Full { (PROLOG, DOCTYPE) } else { ("", "") };
        let title = if self.markup == Markup::Tiny {
            format!("{n}/{total}")
        } else {
            format!("{} ({n}/{total})", self.title())
        };
        let head = format!(
            "{prolog}{doctype}{HTML_OPEN}<head><title>{title}</title><base href=\"{}\"/></head><body>",
            escape(self.home)
        );
        let (prev, next, home) = if self.markup == Markup::Tiny {
            ("&lt;", "&gt;", "^")
        } else {
            ("Anterior", "Siguiente", "Inicio")
        };
        let mut nav = Vec::new();
        if n > 1 {
            nav.push(format!("<a href=\"/p/{}/{}\">{prev}</a>", self.id, n - 1));
        }
        if n < total {
            nav.push(format!("<a href=\"/p/{}/{}\">{next}</a>", self.id, n + 1));
        }
        nav.push(format!("<a href=\"/\">{home}</a>"));
        let note = if truncated && n == total { TRUNCATED_NOTE } else { "" };
        let tail = format!("{note}<p>{}</p></body></html>", nav.join(" | "));
        (head, tail)
    }

    /// Largest chrome of any page (all links present, widest numbers, the truncation note).
    fn chrome_max(&self, max_pages: usize) -> usize {
        let (head, tail) = self.chrome(max_pages.max(2) - 1, max_pages.max(2), true);
        head.len() + tail.len() + TRUNCATED_NOTE.len() + 2
    }

    fn inline(&self, i: &Inline) -> String {
        match i {
            Inline::Text(t) => escape(t),
            Inline::Link { text, link } => format!("<a href=\"/l/{}/{link}\">{}</a>", self.id, escape(text)),
            Inline::Br => "<br/>".to_string(),
        }
    }

    fn inlines(&self, v: &[Inline]) -> String {
        v.iter().map(|i| self.inline(i)).collect()
    }

    fn wrap(heading: bool) -> (&'static str, &'static str) {
        if heading { ("<p><b>", "</b></p>") } else { ("<p>", "</p>") }
    }

    fn form(&self, action: usize, fields: &[Field]) -> String {
        let mut out = format!("<form action=\"/l/{}/{action}\" method=\"get\"><p>", self.id);
        let mut submit = false;
        for field in fields {
            match field {
                Field::Text { name, value } => {
                    out.push_str(&format!("<input type=\"text\" name=\"{}\" size=\"12\"", escape(name)));
                    if !value.is_empty() {
                        out.push_str(&format!(" value=\"{}\"", escape(value)));
                    }
                    out.push_str("/>");
                }
                Field::Hidden { name, value } => {
                    out.push_str(&format!(
                        "<input type=\"hidden\" name=\"{}\" value=\"{}\"/>",
                        escape(name),
                        escape(value)
                    ));
                }
                Field::Submit { name, value } => {
                    submit = true;
                    let name = name.as_ref().map(|n| format!(" name=\"{}\"", escape(n))).unwrap_or_default();
                    out.push_str(&format!("<input type=\"submit\"{name} value=\"{}\"/>", escape(value)));
                }
            }
        }
        if !submit {
            out.push_str("<input type=\"submit\" value=\"Ir\"/>");
        }
        out.push_str("</p></form>");
        out
    }
}

/// Bytes of escaped `text`, and where it can be cut to fit `room`: the end of the last sentence,
/// else the last space, else (when `force`) the last character that fits.
fn split_text(text: &str, room: usize, force: bool) -> Option<(String, String)> {
    let mut used = 0;
    let mut fit = 0;
    let mut sentence = None;
    let mut space = None;
    let mut prev = ' ';
    for (i, c) in text.char_indices() {
        let cost = escape(c.encode_utf8(&mut [0; 4])).len();
        if used + cost > room {
            break;
        }
        used += cost;
        fit = i + c.len_utf8();
        if c == ' ' {
            if matches!(prev, '.' | '!' | '?' | ';' | ':') {
                sentence = Some(i);
            }
            space = Some(i);
        }
        prev = c;
    }
    if fit >= text.len() {
        return Some((text.to_string(), String::new()));
    }
    let cut = match (sentence, space) {
        (Some(s), _) if s * 5 >= fit * 2 => s,
        (_, Some(s)) if s > 0 => s,
        _ if force && fit > 0 => fit,
        _ => return None,
    };
    Some((text[..cut].trim_end().to_string(), text[cut..].trim_start().to_string()))
}

impl Layout<'_> {
    /// The part of `v` that fits `room` bytes, and the rest.
    fn split_inlines(&self, v: &[Inline], room: usize, force: bool) -> (Vec<Inline>, Vec<Inline>) {
        let mut head = Vec::new();
        let mut used = 0;
        for (i, item) in v.iter().enumerate() {
            let cost = self.inline(item).len();
            if used + cost <= room {
                head.push(item.clone());
                used += cost;
                continue;
            }
            let first = force && head.is_empty();
            let mut tail: Vec<Inline> = Vec::new();
            match item {
                Inline::Text(t) => match split_text(t, room - used, first) {
                    Some((a, b)) => {
                        if !a.is_empty() {
                            head.push(Inline::Text(a));
                        }
                        if !b.is_empty() {
                            tail.push(Inline::Text(b));
                        }
                    }
                    None => tail.push(item.clone()),
                },
                // A link that does not fit an empty page loses its target.
                Inline::Link { text, .. } if first => match split_text(text, room, true) {
                    Some((a, b)) => {
                        head.push(Inline::Text(a));
                        if !b.is_empty() {
                            tail.push(Inline::Text(b));
                        }
                    }
                    None => {}
                },
                _ => tail.push(item.clone()),
            }
            tail.extend_from_slice(&v[i + 1..]);
            while head.last() == Some(&Inline::Br) {
                head.pop();
            }
            // Do not leave a lone list bullet or a word or two behind: move the whole block.
            let head_chars: usize = head
                .iter()
                .map(|i| match i {
                    Inline::Text(t) => t.trim().chars().count(),
                    Inline::Link { .. } => MIN_HEAD_CHARS,
                    Inline::Br => 0,
                })
                .sum();
            if !force && head_chars < MIN_HEAD_CHARS {
                return (Vec::new(), v.to_vec());
            }
            while tail.first() == Some(&Inline::Br) {
                tail.remove(0);
            }
            return (head, tail);
        }
        (head, Vec::new())
    }

    /// Content of every page, and whether pages were dropped past `max_pages`.
    fn pages(&self, room: usize, max_pages: usize) -> (Vec<String>, bool) {
        let mut pages = Vec::new();
        let mut cur = String::new();
        for block in &self.doc.blocks {
            let (heading, mut rest): (bool, Vec<Inline>) = match block {
                Block::Heading(v) => (true, v.clone()),
                Block::Para(v) => (false, v.clone()),
                Block::Form { action, fields } => {
                    let form = self.form(*action, fields);
                    if cur.len() + form.len() > room && !cur.is_empty() {
                        pages.push(std::mem::take(&mut cur));
                    }
                    if form.len() <= room {
                        cur.push_str(&form);
                    }
                    continue;
                }
            };
            let (open, close) = Self::wrap(heading);
            loop {
                let rendered = self.inlines(&rest);
                let wrapper = open.len() + close.len();
                if cur.len() + wrapper + rendered.len() <= room {
                    cur.push_str(&format!("{open}{rendered}{close}"));
                    break;
                }
                let left = room.saturating_sub(cur.len() + wrapper);
                let fresh = cur.is_empty();
                if left >= MIN_SPLIT_BYTES || fresh {
                    let (head, tail) = self.split_inlines(&rest, left, fresh);
                    if !head.is_empty() {
                        cur.push_str(&format!("{open}{}{close}", self.inlines(&head)));
                    }
                    if !cur.is_empty() {
                        pages.push(std::mem::take(&mut cur));
                    }
                    // Nothing fits even an empty page: the rest of the block is dropped.
                    if tail.is_empty() || (head.is_empty() && fresh) {
                        break;
                    }
                    rest = tail;
                } else {
                    pages.push(std::mem::take(&mut cur));
                }
            }
            if pages.len() > max_pages {
                break;
            }
        }
        if !cur.is_empty() || pages.is_empty() {
            pages.push(cur);
        }
        let truncated = pages.len() > max_pages;
        pages.truncate(max_pages);
        (pages, truncated)
    }
}

/// Page `n` (from 1) of a document for replies of `page_bytes`, with the number of pages; `None`
/// when there is no such page or the reply is too small for any page.
pub fn render_page(doc: &Document, id: u32, n: usize, page_bytes: usize, max_pages: usize, home: &str) -> Option<(String, usize)> {
    let layout = Layout {
        doc,
        id,
        home,
        markup: Markup::for_size(page_bytes),
    };
    let room = page_bytes.checked_sub(layout.chrome_max(max_pages))?;
    if room < MIN_CONTENT_BYTES {
        return None;
    }
    let (pages, truncated) = layout.pages(room, max_pages);
    let total = pages.len();
    let content = pages.get(n.checked_sub(1)?)?;
    let (head, tail) = layout.chrome(n, total, truncated);
    Some((format!("{head}{content}{tail}"), total))
}

/// Test helper: `page` is well-formed XML with matching end tags.
#[cfg(test)]
pub(crate) fn assert_well_formed(page: &str) {
    let mut reader = quick_xml::Reader::from_str(page);
    reader.config_mut().check_end_names = true;
    let mut depth = 0i32;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(quick_xml::events::Event::Start(_)) => depth += 1,
            Ok(quick_xml::events::Event::End(_)) => depth -= 1,
            Ok(_) => {}
            Err(e) => panic!("not well-formed ({e}): {page}"),
        }
    }
    assert_eq!(depth, 0, "unbalanced: {page}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sndcp::wapgw::convert::convert_html;
    use url::Url;

    fn para(text: &str) -> Block {
        Block::Para(vec![Inline::Text(text.to_string())])
    }

    fn doc(blocks: Vec<Block>) -> Document {
        Document {
            title: "Doc & co".to_string(),
            blocks,
            links: vec!["http://example.org/a".to_string()],
            refresh: None,
        }
    }

    const HOME: &str = "http://10.0.0.1/";

    #[test]
    fn short_document_is_one_page() {
        let d = doc(vec![
            para("Hola <mundo>"),
            Block::Para(vec![Inline::Link {
                text: "enlace".into(),
                link: 0,
            }]),
        ]);
        let (page, total) = render_page(&d, 7, 1, 1200, 40, HOME).unwrap();
        assert_eq!(total, 1);
        assert!(page.starts_with("<?xml"));
        assert!(page.contains("<title>Doc &amp; co (1/1)</title><base href=\"http://10.0.0.1/\"/>"));
        assert!(page.contains("<p>Hola &lt;mundo&gt;</p><p><a href=\"/l/7/0\">enlace</a></p>"));
        assert!(page.ends_with("<p><a href=\"/\">Inicio</a></p></body></html>"));
        assert_well_formed(&page);
        assert_eq!(render_page(&d, 7, 2, 1200, 40, HOME), None);
        assert_eq!(render_page(&d, 7, 0, 1200, 40, HOME), None);
    }

    #[test]
    fn long_document_pages_fit_and_link_each_other() {
        let sentence = "Esta es una frase de prueba con algo de texto. ";
        let blocks: Vec<Block> = (0..30).map(|_| para(sentence.repeat(5).trim_end())).collect();
        let d = doc(blocks);
        let (first, total) = render_page(&d, 3, 1, 1200, 40, HOME).unwrap();
        assert!(total > 5, "{total} pages");
        assert!(first.contains("<a href=\"/p/3/2\">Siguiente</a>") && !first.contains("Anterior"));
        let mut words = 0;
        for n in 1..=total {
            let (page, t) = render_page(&d, 3, n, 1200, 40, HOME).unwrap();
            assert_eq!(t, total);
            assert!(page.len() <= 1200, "page {n}: {} bytes", page.len());
            assert_well_formed(&page);
            words += page.matches("frase").count();
            if n > 1 && n < total {
                assert!(page.contains(&format!("<a href=\"/p/3/{}\">Anterior</a>", n - 1)));
                assert!(page.contains(&format!("<a href=\"/p/3/{}\">Siguiente</a>", n + 1)));
            }
            // Cut at the end of a sentence: every page's text ends with a full stop.
            let body_end = page.rfind("</p><p><a href=").unwrap();
            assert!(page[..body_end].ends_with('.'), "page {n} ends mid-sentence: {}", &page[..body_end]);
        }
        assert_eq!(words, 30 * 5, "no text lost or repeated");
    }

    #[test]
    fn max_pages_truncates_with_note() {
        let blocks: Vec<Block> = (0..50)
            .map(|i| para(&format!("Párrafo número {i} con relleno suficiente para ocupar sitio.")))
            .collect();
        let d = doc(blocks);
        let (last, total) = render_page(&d, 1, 3, 500, 3, HOME).unwrap();
        assert_eq!(total, 3);
        assert!(last.contains("(Documento recortado)"));
        assert!(last.len() <= 500);
        assert_well_formed(&last);
    }

    #[test]
    fn small_replies_use_compact_markup() {
        let d = doc((0..10).map(|_| para("Texto corto de ejemplo. ")).collect());
        let (page, _) = render_page(&d, 1, 1, 500, 40, HOME).unwrap();
        assert!(!page.starts_with("<?xml") && page.contains("Siguiente") && page.len() <= 500);
        let (tiny, _) = render_page(&d, 1, 1, 300, 40, HOME).unwrap();
        assert!(tiny.len() <= 300 && tiny.contains("&gt;"), "{tiny}");
        assert_well_formed(&tiny);
        assert_eq!(render_page(&d, 1, 1, 150, 40, HOME), None, "no room for content");
    }

    #[test]
    fn huge_word_and_huge_link_still_progress() {
        let d = doc(vec![
            para(&"x".repeat(3000)),
            Block::Para(vec![Inline::Link {
                text: "y".repeat(90),
                link: 0,
            }]),
        ]);
        let (_, total) = render_page(&d, 1, 1, 300, 200, HOME).unwrap();
        let mut xs = 0;
        for n in 1..=total {
            let (page, _) = render_page(&d, 1, n, 300, 200, HOME).unwrap();
            assert!(page.len() <= 300);
            assert_well_formed(&page);
            xs += page.matches('x').count() - HTML_OPEN.matches('x').count();
        }
        assert_eq!(xs, 3000);
    }

    #[test]
    fn no_lone_bullet_at_the_bottom_of_a_page() {
        let item = |i: usize| {
            Block::Para(vec![
                Inline::Text("- ".to_string()),
                Inline::Link {
                    text: format!("Titular largo número {i} de una lista de noticias de prueba"),
                    link: 0,
                },
            ])
        };
        let d = doc((0..20).map(item).collect());
        let (_, total) = render_page(&d, 1, 1, 1200, 40, HOME).unwrap();
        for n in 1..=total {
            let (page, _) = render_page(&d, 1, n, 1200, 40, HOME).unwrap();
            assert!(!page.contains("<p>- </p>"), "page {n}: {page}");
        }
    }

    #[test]
    fn forms_render_as_get_through_the_gateway() {
        let html = r#"<form action="/lite/"><input type="text" name="q"><input type="hidden" name="kl" value="es-es"></form>"#;
        let d = convert_html(html, &Url::parse("http://lite.example.com/").unwrap());
        let (page, _) = render_page(&d, 9, 1, 1200, 40, HOME).unwrap();
        assert!(page.contains(
            "<form action=\"/l/9/0\" method=\"get\"><p><input type=\"text\" name=\"q\" size=\"12\"/><input type=\"hidden\" name=\"kl\" value=\"es-es\"/><input type=\"submit\" value=\"Ir\"/></p></form>"
        ));
        assert_well_formed(&page);
    }
}
