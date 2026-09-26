//! Web pages to small documents for a WAP browser.
//!
//! A tolerant, single-pass tokenizer (no DOM, no dependency) turns HTML, XHTML or WML into a flat
//! [`Document`]: headings, paragraphs of text and links, and simple GET forms. Scripts, styles,
//! images, embedded objects and hidden elements are dropped; when the page has a `<main>` (or a
//! single `<article>`), only that part is kept. Links are made absolute and numbered, so the pages
//! can carry short gateway links instead of long URLs.
//!
//! WAP content (WML, XHTML-MP) that already fits the reply goes out as it is, only trimmed
//! ([`trim_wap_markup`]).

use std::borrow::Cow;

use url::Url;

/// Longest link text kept (a link cannot be split across pages).
const MAX_LINK_TEXT: usize = 100;
/// A meta refresh is followed when it fires within this many seconds.
const MAX_REFRESH_DELAY: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    Text(String),
    /// Link number `link` in [`Document::links`].
    Link {
        text: String,
        link: usize,
    },
    Br,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Text { name: String, value: String },
    Hidden { name: String, value: String },
    Submit { name: Option<String>, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Heading(Vec<Inline>),
    Para(Vec<Inline>),
    /// A GET form; `action` is a link number.
    Form {
        action: usize,
        fields: Vec<Field>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Document {
    pub title: String,
    pub blocks: Vec<Block>,
    /// Absolute http/https URLs, numbered by position.
    pub links: Vec<String>,
    /// Target of a `<meta http-equiv="refresh">` that fires almost at once.
    pub refresh: Option<String>,
}

impl Document {
    /// Rough memory footprint, for the document cache.
    pub fn approx_bytes(&self) -> usize {
        let inline_bytes = |v: &Vec<Inline>| {
            v.iter()
                .map(|i| match i {
                    Inline::Text(t) | Inline::Link { text: t, .. } => t.len() + 16,
                    Inline::Br => 8,
                })
                .sum::<usize>()
        };
        let blocks: usize = self
            .blocks
            .iter()
            .map(|b| match b {
                Block::Heading(v) | Block::Para(v) => inline_bytes(v) + 32,
                Block::Form { fields, .. } => fields.len() * 64 + 32,
            })
            .sum();
        blocks + self.links.iter().map(|l| l.len() + 24).sum::<usize>() + self.title.len() + 64
    }

    /// Characters of text, links included.
    pub fn text_len(&self) -> usize {
        self.blocks
            .iter()
            .map(|b| match b {
                Block::Heading(v) | Block::Para(v) => v
                    .iter()
                    .map(|i| match i {
                        Inline::Text(t) | Inline::Link { text: t, .. } => t.chars().count(),
                        Inline::Br => 0,
                    })
                    .sum(),
                Block::Form { .. } => 0,
            })
            .sum()
    }
}

// ---------------------------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token<'a> {
    Start {
        name: String,
        attrs: Vec<(String, String)>,
        self_closing: bool,
    },
    End {
        name: String,
    },
    /// Text as written (entities not decoded yet).
    Text(&'a str),
}

/// Elements whose content is text up to their end tag, whatever it contains.
const RAW_TEXT: [&str; 8] = ["script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes"];

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    raw_until: Option<String>,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            pos: 0,
            raw_until: None,
        }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    /// Byte offset (from `pos`) of `needle`, ASCII case-insensitive.
    fn find_ci(&self, needle: &str) -> Option<usize> {
        let hay = self.rest().as_bytes();
        let needle = needle.as_bytes();
        hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
    }

    fn skip_past(&mut self, end: &str) {
        match self.rest().find(end) {
            Some(i) => self.pos += i + end.len(),
            None => self.pos = self.src.len(),
        }
    }

    fn tag_name(&mut self) -> String {
        let rest = self.rest();
        let len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_')))
            .unwrap_or(rest.len());
        self.pos += len;
        rest[..len].to_ascii_lowercase()
    }

    fn skip_ws(&mut self) {
        let rest = self.rest();
        self.pos += rest.len() - rest.trim_start().len();
    }

    /// Attributes and the closing `>` of a start tag, `pos` just after its name.
    fn attributes(&mut self) -> (Vec<(String, String)>, bool) {
        let mut attrs = Vec::new();
        loop {
            self.skip_ws();
            let rest = self.rest();
            if rest.is_empty() {
                return (attrs, false);
            }
            if rest.starts_with("/>") {
                self.pos += 2;
                return (attrs, true);
            }
            if rest.starts_with('>') {
                self.pos += 1;
                return (attrs, false);
            }
            if rest.starts_with('/') {
                self.pos += 1;
                continue;
            }
            let len = rest
                .find(|c: char| c.is_whitespace() || matches!(c, '=' | '>' | '/'))
                .unwrap_or(rest.len())
                .max(1.min(rest.len()));
            let name = rest[..len].to_ascii_lowercase();
            self.pos += len;
            self.skip_ws();
            let mut value = String::new();
            if self.rest().starts_with('=') {
                self.pos += 1;
                self.skip_ws();
                let rest = self.rest();
                match rest.chars().next() {
                    Some(q @ ('"' | '\'')) => {
                        let body = &rest[1..];
                        let end = body.find(q).unwrap_or(body.len());
                        value = body[..end].to_string();
                        self.pos += 1 + end + usize::from(end < body.len());
                    }
                    _ => {
                        let end = rest.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(rest.len());
                        value = rest[..end].to_string();
                        self.pos += end;
                    }
                }
            }
            if !name.is_empty() && !attrs.iter().any(|(n, _)| *n == name) {
                attrs.push((name, value));
            }
        }
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        loop {
            if self.pos >= self.src.len() {
                return None;
            }
            if let Some(tag) = self.raw_until.take() {
                let end = self.find_ci(&format!("</{tag}")).unwrap_or(self.rest().len());
                let text = &self.rest()[..end];
                self.pos += end;
                if !text.is_empty() {
                    return Some(Token::Text(text));
                }
                continue;
            }
            let rest = self.rest();
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                self.pos += end;
                return Some(Token::Text(&rest[..end]));
            }
            let after = &rest[1..];
            if after.starts_with("!--") {
                self.pos += 4;
                self.skip_past("-->");
            } else if after.starts_with("![CDATA[") {
                let body = &after[8..];
                let end = body.find("]]>").unwrap_or(body.len());
                self.pos += 9 + end + if end < body.len() { 3 } else { 0 };
                return Some(Token::Text(&body[..end]));
            } else if after.starts_with('!') || after.starts_with('?') {
                self.skip_past(">");
            } else if after.starts_with('/') && after[1..].starts_with(|c: char| c.is_ascii_alphabetic()) {
                self.pos += 2;
                let name = self.tag_name();
                self.skip_past(">");
                return Some(Token::End { name });
            } else if after.starts_with(|c: char| c.is_ascii_alphabetic()) {
                self.pos += 1;
                let name = self.tag_name();
                let (attrs, self_closing) = self.attributes();
                if !self_closing && RAW_TEXT.contains(&name.as_str()) {
                    self.raw_until = Some(name.clone());
                }
                return Some(Token::Start { name, attrs, self_closing });
            } else {
                // A lone '<' in text.
                self.pos += 1;
                return Some(Token::Text("<"));
            }
        }
    }
}

fn attr<'b>(attrs: &'b [(String, String)], name: &str) -> Option<&'b str> {
    attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------------------------
// Entities and escaping
// ---------------------------------------------------------------------------------------------

const ENTITIES: [(&str, char); 64] = [
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
    ("iexcl", '¡'),
    ("cent", '¢'),
    ("pound", '£'),
    ("euro", '€'),
    ("yen", '¥'),
    ("sect", '§'),
    ("copy", '©'),
    ("reg", '®'),
    ("trade", '™'),
    ("ordf", 'ª'),
    ("ordm", 'º'),
    ("laquo", '«'),
    ("raquo", '»'),
    ("deg", '°'),
    ("plusmn", '±'),
    ("middot", '·'),
    ("para", '¶'),
    ("iquest", '¿'),
    ("times", '×'),
    ("divide", '÷'),
    ("frac12", '½'),
    ("aacute", 'á'),
    ("eacute", 'é'),
    ("iacute", 'í'),
    ("oacute", 'ó'),
    ("uacute", 'ú'),
    ("Aacute", 'Á'),
    ("Eacute", 'É'),
    ("Iacute", 'Í'),
    ("Oacute", 'Ó'),
    ("Uacute", 'Ú'),
    ("agrave", 'à'),
    ("egrave", 'è'),
    ("ograve", 'ò'),
    ("ntilde", 'ñ'),
    ("Ntilde", 'Ñ'),
    ("uuml", 'ü'),
    ("Uuml", 'Ü'),
    ("auml", 'ä'),
    ("ouml", 'ö'),
    ("ccedil", 'ç'),
    ("Ccedil", 'Ç'),
    ("szlig", 'ß'),
    ("ndash", '–'),
    ("mdash", '—'),
    ("lsquo", '‘'),
    ("rsquo", '’'),
    ("sbquo", '‚'),
    ("ldquo", '“'),
    ("rdquo", '”'),
    ("bdquo", '„'),
    ("hellip", '…'),
    ("bull", '•'),
    ("prime", '′'),
    ("larr", '←'),
    ("rarr", '→'),
    ("shy", '\u{ad}'),
    ("zwnj", '\u{200c}'),
];

/// Decode character references (`&amp;`, `&#233;`, `&#xE9;`); unknown ones stay as written.
pub fn decode_entities(s: &str) -> Cow<'_, str> {
    if !s.contains('&') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let body_end = rest[1..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '#'))
            .map(|e| e + 1)
            .unwrap_or(rest.len());
        let body = &rest[1..body_end];
        let has_semicolon = rest[body_end..].starts_with(';');
        let decoded = if let Some(num) = body.strip_prefix('#') {
            let code = match num.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => num.parse::<u32>().ok(),
            };
            code.map(|c| char::from_u32(c).filter(|c| *c != '\0').unwrap_or('\u{fffd}'))
        } else if has_semicolon || matches!(body, "amp" | "lt" | "gt" | "quot" | "nbsp") {
            ENTITIES.iter().find(|(n, _)| *n == body).map(|(_, c)| *c)
        } else {
            None
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[body_end + usize::from(has_semicolon)..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// XML-safe text: `& < > "` escaped, characters XML 1.0 does not allow dropped.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' | '\n' | '\r' => out.push(' '),
            c if (c as u32) < 0x20 || matches!(c, '\u{fffe}' | '\u{ffff}') => {}
            c => out.push(c),
        }
    }
    out
}

/// Collapse runs of whitespace (non-breaking spaces included) into one space.
fn collapse_ws(s: &str, out: &mut String) {
    for c in s.chars() {
        if c.is_whitespace() || c == '\u{a0}' {
            if !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
            }
        } else if !matches!(c, '\u{ad}' | '\u{200b}') {
            out.push(c);
        }
    }
}

fn cut_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    let cut = match cut.rfind(' ') {
        Some(i) if i > max / 2 => cut[..i].to_string(),
        _ => cut,
    };
    format!("{}…", cut.trim_end())
}

// ---------------------------------------------------------------------------------------------
// HTML / WML to Document
// ---------------------------------------------------------------------------------------------

/// Subtrees that never carry readable text.
const DROP: [&str; 20] = [
    "script", "style", "noscript", "template", "iframe", "object", "embed", "applet", "svg", "math", "canvas", "video", "audio", "select",
    "textarea", "button", "aside", "datalist", "dialog", "frameset",
];
/// Elements that start and end a line of text.
const BLOCK_TAGS: [&str; 30] = [
    "p",
    "div",
    "section",
    "article",
    "main",
    "header",
    "footer",
    "nav",
    "ul",
    "ol",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "tr",
    "blockquote",
    "pre",
    "hr",
    "fieldset",
    "address",
    "figure",
    "figcaption",
    "center",
    "card",
    "details",
    "summary",
    "caption",
    "tbody",
    "body",
];
/// Void elements (never have an end tag).
const VOID: [&str; 15] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr", "go",
];

fn is_heading(name: &str) -> bool {
    matches!(name, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}

fn is_hidden(attrs: &[(String, String)]) -> bool {
    if attr(attrs, "hidden").is_some() || attr(attrs, "aria-hidden").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return true;
    }
    attr(attrs, "style").is_some_and(|s| {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase();
        s.contains("display:none") || s.contains("visibility:hidden")
    })
}

/// `content` of a meta refresh: "5; url=http://..." -> (5, "http://...").
fn parse_refresh(content: &str) -> Option<(u32, &str)> {
    let (delay, rest) = content.split_once([';', ','])?;
    let delay: u32 = delay.trim().split('.').next()?.parse().ok()?;
    let rest = rest.trim();
    let target = rest
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("url="))
        .map(|_| &rest[4..])
        .unwrap_or(rest)
        .trim()
        .trim_matches(['"', '\'']);
    (!target.is_empty()).then_some((delay, target))
}

struct OpenLink {
    link: Option<usize>,
    text: String,
    /// Alt text of an image inside the link, for links without text.
    alt: String,
}

struct OpenForm {
    action: usize,
    fields: Vec<Field>,
}

struct Builder {
    base: Url,
    doc: Document,
    para: Vec<Inline>,
    heading: bool,
    link: Option<OpenLink>,
    form: Option<OpenForm>,
    /// WML `<do>` label waiting for its `<go>`.
    do_label: Option<String>,
    pre: usize,
    /// Heading blocks emitted so far.
    headings: usize,
}

impl Builder {
    fn link_index(&mut self, href: &str) -> Option<usize> {
        let href = decode_entities(href.trim());
        let url = self.base.join(&href).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let mut url = url;
        url.set_fragment(None);
        let s = url.to_string();
        Some(match self.doc.links.iter().position(|l| *l == s) {
            Some(i) => i,
            None => {
                self.doc.links.push(s);
                self.doc.links.len() - 1
            }
        })
    }

    fn push_text(&mut self, text: &str) {
        if let Some(link) = self.link.as_mut() {
            collapse_ws(text, &mut link.text);
            return;
        }
        if self.pre > 0 {
            for (i, line) in text.split('\n').enumerate() {
                if i > 0 {
                    self.br();
                }
                self.push_plain(line);
            }
        } else {
            self.push_plain(text);
        }
    }

    fn push_plain(&mut self, text: &str) {
        let at_line_start = matches!(self.para.last(), None | Some(Inline::Br));
        match self.para.last_mut() {
            Some(Inline::Text(t)) => collapse_ws(text, t),
            _ => {
                let mut t = String::new();
                if !at_line_start && text.starts_with(|c: char| c.is_whitespace()) {
                    t.push(' ');
                }
                collapse_ws(text, &mut t);
                if at_line_start {
                    t = t.trim_start().to_string();
                }
                if !t.is_empty() {
                    self.para.push(Inline::Text(t));
                }
            }
        }
    }

    fn br(&mut self) {
        if let Some(Inline::Text(t)) = self.para.last_mut() {
            let trimmed = t.trim_end().len();
            t.truncate(trimmed);
        }
        if !self.para.is_empty() && self.para.last() != Some(&Inline::Br) {
            self.para.push(Inline::Br);
        }
    }

    fn close_link(&mut self) {
        let Some(open) = self.link.take() else { return };
        let text = if open.text.trim().is_empty() { open.alt } else { open.text };
        let text = cut_chars(text.trim(), MAX_LINK_TEXT);
        match open.link {
            Some(link) if !text.is_empty() => {
                // Keep a link apart from the word or link before it.
                let glued = match self.para.last() {
                    Some(Inline::Text(t)) => !t.ends_with(' '),
                    Some(Inline::Link { .. }) => true,
                    _ => false,
                };
                if glued {
                    self.push_plain(" ");
                }
                self.para.push(Inline::Link { text, link });
            }
            _ => self.push_plain(&text),
        }
    }

    fn flush(&mut self) {
        self.close_link();
        while matches!(self.para.last(), Some(Inline::Br)) {
            self.para.pop();
        }
        if let Some(Inline::Text(t)) = self.para.last_mut() {
            let trimmed = t.trim_end().len();
            t.truncate(trimmed);
        }
        let para = std::mem::take(&mut self.para);
        let has_content = para.iter().any(|i| match i {
            Inline::Text(t) => !t.trim().is_empty(),
            _ => true,
        });
        if has_content {
            if self.heading {
                self.headings += 1;
                self.doc.blocks.push(Block::Heading(para));
            } else {
                self.doc.blocks.push(Block::Para(para));
            }
        }
    }

    fn close_form(&mut self) {
        let Some(form) = self.form.take() else { return };
        if form.fields.iter().any(|f| matches!(f, Field::Text { .. })) {
            self.flush();
            self.doc.blocks.push(Block::Form {
                action: form.action,
                fields: form.fields,
            });
        }
    }

    fn start(&mut self, name: &str, attrs: &[(String, String)]) {
        if BLOCK_TAGS.contains(&name) || is_heading(name) || name == "form" {
            self.flush();
            self.heading = is_heading(name);
        }
        match name {
            "br" => {
                self.close_link();
                self.br();
            }
            "li" | "dd" => self.push_plain("- "),
            "td" | "th" => self.push_plain(" "),
            "pre" => self.pre += 1,
            "card" => {
                if let Some(title) = attr(attrs, "title").filter(|t| !t.trim().is_empty()) {
                    self.doc.blocks.push(Block::Heading(vec![Inline::Text(cut_chars(
                        decode_entities(title).trim(),
                        MAX_LINK_TEXT,
                    ))]));
                }
            }
            "a" | "anchor" => {
                self.close_link();
                let link = attr(attrs, "href").and_then(|h| self.link_index(h));
                self.link = Some(OpenLink {
                    link,
                    text: String::new(),
                    alt: String::new(),
                });
            }
            "go" => {
                let target = attr(attrs, "href").and_then(|h| self.link_index(h));
                if let Some(open) = self.link.as_mut() {
                    open.link = open.link.or(target);
                } else if let (Some(label), Some(link)) = (self.do_label.take(), target) {
                    self.close_link();
                    self.push_plain(" ");
                    self.para.push(Inline::Link { text: label, link });
                }
            }
            "do" => {
                let label = attr(attrs, "label").or(attr(attrs, "type")).unwrap_or("OK");
                self.do_label = Some(cut_chars(decode_entities(label).trim(), MAX_LINK_TEXT));
            }
            "img" => {
                if let (Some(open), Some(alt)) = (self.link.as_mut(), attr(attrs, "alt")) {
                    collapse_ws(&decode_entities(alt), &mut open.alt);
                }
            }
            "form" => {
                self.close_form();
                if !attr(attrs, "method").is_none_or(|m| m.eq_ignore_ascii_case("get")) {
                    return;
                }
                let action = attr(attrs, "action").unwrap_or("");
                let action = if action.trim().is_empty() {
                    let base = self.base.to_string();
                    self.link_index(&base)
                } else {
                    self.link_index(action)
                };
                if let Some(action) = action {
                    self.form = Some(OpenForm {
                        action,
                        fields: Vec::new(),
                    });
                }
            }
            "input" => {
                let Some(form) = self.form.as_mut() else { return };
                let name = attr(attrs, "name").map(|n| decode_entities(n).into_owned());
                let value = decode_entities(attr(attrs, "value").unwrap_or("")).into_owned();
                let kind = attr(attrs, "type").unwrap_or("text").to_ascii_lowercase();
                let field = match (kind.as_str(), name) {
                    ("text" | "search" | "email" | "url" | "tel" | "number", Some(name)) => Some(Field::Text { name, value }),
                    ("hidden", Some(name)) => Some(Field::Hidden { name, value }),
                    ("submit" | "image", name) => Some(Field::Submit {
                        name,
                        value: if value.is_empty() {
                            "Ir".to_string()
                        } else {
                            cut_chars(&value, 20)
                        },
                    }),
                    _ => None,
                };
                if let Some(field) = field
                    && form.fields.len() < 12
                {
                    form.fields.push(field);
                }
            }
            _ => {}
        }
    }

    fn end(&mut self, name: &str) {
        match name {
            "a" | "anchor" => self.close_link(),
            "do" => self.do_label = None,
            "pre" => self.pre = self.pre.saturating_sub(1),
            "form" => self.close_form(),
            _ => {}
        }
        if BLOCK_TAGS.contains(&name) || is_heading(name) {
            self.flush();
            self.heading = false;
        }
    }
}

/// The element whose content is kept: the `<main>` (or `role="main"`), else the only `<article>`.
fn content_root(src: &str) -> Option<(String, usize)> {
    let mut articles = Vec::new();
    for (i, token) in Lexer::new(src).enumerate() {
        if let Token::Start { name, attrs, .. } = token {
            if name == "main" || attr(&attrs, "role") == Some("main") {
                return Some((name, i));
            }
            if name == "article" {
                articles.push(i);
            }
        }
    }
    (articles.len() == 1).then(|| ("article".to_string(), articles[0]))
}

/// Convert an HTML, XHTML or WML page fetched from `base`.
pub fn convert_html(src: &str, base: &Url) -> Document {
    let root = content_root(src);
    let mut b = Builder {
        base: base.clone(),
        doc: Document::default(),
        para: Vec::new(),
        heading: false,
        link: None,
        form: None,
        do_label: None,
        pre: 0,
        headings: 0,
    };
    let mut title = String::new();
    let mut in_title = false;
    let mut first_heading = String::new();
    // Subtree being skipped: (element name, nesting depth).
    let mut skip: Option<(String, usize)> = None;
    // Inside the content root: (element name, nesting depth); None before or after it.
    let mut inside: Option<(String, usize)> = None;
    let mut root_done = false;

    for (i, token) in Lexer::new(src).enumerate() {
        // Head data is read wherever it is.
        match &token {
            Token::Start { name, .. } if name == "title" => {
                in_title = title.is_empty();
                continue;
            }
            Token::End { name } if name == "title" => {
                in_title = false;
                continue;
            }
            Token::Text(t) if in_title => {
                collapse_ws(&decode_entities(t), &mut title);
                continue;
            }
            Token::Start { name, attrs, .. } if name == "base" => {
                if let Some(base) = attr(attrs, "href").and_then(|h| b.base.join(h.trim()).ok()) {
                    b.base = base;
                }
                continue;
            }
            Token::Start { name, attrs, .. } if name == "meta" => {
                let refresh = attr(attrs, "http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh"));
                if let Some((delay, target)) = attr(attrs, "content").filter(|_| refresh).and_then(parse_refresh)
                    && delay <= MAX_REFRESH_DELAY
                    && b.doc.refresh.is_none()
                    && let Ok(url) = b.base.join(&decode_entities(target))
                    && matches!(url.scheme(), "http" | "https")
                {
                    b.doc.refresh = Some(url.to_string());
                }
                continue;
            }
            _ => {}
        }

        if let Some((root_name, root_index)) = &root {
            if root_done {
                break;
            }
            match (&token, inside.as_mut()) {
                (_, None) if i == *root_index => {
                    inside = Some((root_name.clone(), 1));
                    continue;
                }
                (_, None) => continue,
                (Token::Start { name, self_closing, .. }, Some((n, depth))) if name == n && !self_closing => *depth += 1,
                (Token::End { name }, Some((n, depth))) if name == n => {
                    *depth -= 1;
                    if *depth == 0 {
                        root_done = true;
                        continue;
                    }
                }
                _ => {}
            }
        }

        if let Some((skip_name, depth)) = skip.as_mut() {
            match &token {
                Token::Start { name, self_closing, .. } if name == skip_name && !self_closing => *depth += 1,
                Token::End { name } if name == skip_name => {
                    *depth -= 1;
                    if *depth == 0 {
                        skip = None;
                    }
                }
                _ => {}
            }
            continue;
        }

        match token {
            Token::Text(t) => {
                let text = decode_entities(t);
                if b.heading && b.headings == 0 && first_heading.len() < 200 {
                    collapse_ws(&text, &mut first_heading);
                }
                b.push_text(&text);
            }
            Token::Start { name, attrs, self_closing } => {
                let void = self_closing || VOID.contains(&name.as_str());
                if DROP.contains(&name.as_str()) || (!void && is_hidden(&attrs)) {
                    if !void {
                        skip = Some((name, 1));
                    }
                    continue;
                }
                b.start(&name, &attrs);
                if self_closing && !VOID.contains(&name.as_str()) {
                    b.end(&name);
                }
            }
            Token::End { name } => b.end(&name),
        }
    }
    b.close_form();
    b.flush();

    let title = if !title.trim().is_empty() {
        title
    } else if !first_heading.trim().is_empty() {
        first_heading
    } else {
        base.host_str().unwrap_or("").to_string()
    };
    b.doc.title = cut_chars(title.trim(), 60);
    b.doc
}

/// A `text/plain` body: blank lines separate paragraphs, line breaks are kept.
pub fn convert_text(src: &str, title: &str) -> Document {
    let mut doc = Document {
        title: cut_chars(title, 60),
        ..Default::default()
    };
    for chunk in src.replace("\r\n", "\n").split("\n\n") {
        let mut para = Vec::new();
        for line in chunk.lines() {
            let mut t = String::new();
            collapse_ws(line, &mut t);
            let t = t.trim();
            if t.is_empty() {
                continue;
            }
            if !para.is_empty() {
                para.push(Inline::Br);
            }
            para.push(Inline::Text(t.to_string()));
        }
        if !para.is_empty() {
            doc.blocks.push(Block::Para(para));
        }
    }
    doc
}

/// WAP markup that goes out as it is: comments dropped, whitespace runs collapsed, the XML
/// declaration saying UTF-8 (the body has been converted to it) and, for XHTML-MP, a `<base>`
/// with the page's own URL so relative links keep working when it was asked for through `/go`.
pub fn trim_wap_markup(src: &str, xhtml: bool, url: &Url) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src.trim_start_matches('\u{feff}');
    // XML declaration.
    if rest.starts_with("<?xml") {
        let end = rest.find("?>").map(|e| e + 2).unwrap_or(rest.len());
        out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        rest = &rest[end..];
    }
    let mut in_ws = false;
    let mut chars = rest.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '<' && rest[i..].starts_with("<!--") {
            let end = rest[i..].find("-->").map(|e| i + e + 3).unwrap_or(rest.len());
            while chars.peek().is_some_and(|&(j, _)| j < end) {
                chars.next();
            }
            continue;
        }
        if c.is_whitespace() {
            in_ws = true;
            continue;
        }
        if in_ws && !out.is_empty() && !out.ends_with('>') || in_ws && c != '<' && !out.is_empty() {
            out.push(' ');
        }
        in_ws = false;
        out.push(c);
    }
    if xhtml && !out.to_ascii_lowercase().contains("<base") {
        let lower = out.to_ascii_lowercase();
        if let Some(head) = lower.find("<head>") {
            let at = head + "<head>".len();
            out.insert_str(at, &format!("<base href=\"{}\"/>", escape(url.as_str())));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("http://news.example.org/section/index.html").unwrap()
    }

    fn texts(doc: &Document) -> String {
        let mut out = String::new();
        for block in &doc.blocks {
            match block {
                Block::Heading(v) | Block::Para(v) => {
                    for i in v {
                        match i {
                            Inline::Text(t) => out.push_str(t),
                            Inline::Link { text, link } => out.push_str(&format!("[{text}->{}]", doc.links[*link])),
                            Inline::Br => out.push('|'),
                        }
                    }
                }
                Block::Form { action, fields } => out.push_str(&format!("<form {} {}>", doc.links[*action], fields.len())),
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn tokenizer_survives_scripts_unclosed_tags_and_bare_attributes() {
        let html = r#"<script>if (a<b) document.write("<div>x</div>")</script><p>ok &amp; fine<ul><li>one<li>two</ul>
            <a href=/x?a=1&amp;b=2>l</a><P CLASS=x>Upper</P><!-- <p>hidden</p> --> 1 < 2"#;
        let doc = convert_html(html, &base());
        assert_eq!(
            texts(&doc),
            "ok & fine\n- one\n- two\n[l->http://news.example.org/x?a=1&b=2]\nUpper\n1 < 2\n"
        );
    }

    #[test]
    fn entities() {
        assert_eq!(
            decode_entities("a &amp; b &lt;c&gt; &#233;&#xE9; &euro;5 &bogus; &amp"),
            "a & b <c> éé €5 &bogus; &"
        );
        assert_eq!(decode_entities("caf&eacute;"), "café");
        assert_eq!(escape("a<b & \"c\"\u{1}"), "a&lt;b &amp; &quot;c&quot;");
    }

    #[test]
    fn drops_scripts_styles_images_and_hidden() {
        let html = r#"<html><head><title>T</title><style>p{}</style></head><body>
            <div hidden>secret</div><div style="display: none">gone</div><span aria-hidden="true">x</span>
            <noscript>enable JS</noscript><svg><text>chart</text></svg><img src="a.png" alt="pic">
            <p>visible <img src="b.png"> text</p><select><option>opt</option></select></body></html>"#;
        let doc = convert_html(html, &base());
        assert_eq!(doc.title, "T");
        assert_eq!(texts(&doc), "visible text\n");
    }

    #[test]
    fn main_is_preferred_and_links_are_absolute() {
        let html = r#"<nav><a href="/">Home</a></nav><main><h1>Title <a href="story.html#top">here</a></h1>
            <p>Body with <a href="https://other.example.com/x">a link</a> and <a href="javascript:void(0)">js</a>
            <a href="mailto:x@y">mail</a></p></main><footer>legal</footer>"#;
        let doc = convert_html(html, &base());
        assert_eq!(
            texts(&doc),
            "Title [here->http://news.example.org/section/story.html]\nBody with [a link->https://other.example.com/x] and js mail\n"
        );
        assert!(matches!(doc.blocks[0], Block::Heading(_)));
        assert_eq!(doc.title, "Title here", "first heading when there is no <title>");
    }

    #[test]
    fn many_articles_keep_the_whole_page() {
        let html = "<article><p>one</p></article><article><p>two</p></article>";
        assert_eq!(texts(&convert_html(html, &base())), "one\ntwo\n");
    }

    #[test]
    fn get_forms_are_kept_post_forms_are_not() {
        let html = r#"<form action="/search" method="get">Find: <input type="text" name="q" value="x&amp;y">
            <input type="hidden" name="kl" value="es-es"><input type="checkbox" name="c"><input type="submit" value="Go"></form>
            <form method="post" action="/login"><input name="user"><input type="password" name="pw"></form>"#;
        let doc = convert_html(html, &base());
        assert_eq!(texts(&doc), "Find:\n<form http://news.example.org/search 3>\n");
        let Block::Form { fields, .. } = &doc.blocks[1] else { panic!() };
        assert_eq!(
            fields,
            &vec![
                Field::Text {
                    name: "q".into(),
                    value: "x&y".into()
                },
                Field::Hidden {
                    name: "kl".into(),
                    value: "es-es".into()
                },
                Field::Submit {
                    name: None,
                    value: "Go".into()
                },
            ]
        );
    }

    #[test]
    fn wml_cards_anchors_and_do() {
        let wml = r##"<?xml version="1.0"?><!DOCTYPE wml PUBLIC "-//WAPFORUM//DTD WML 1.1//EN" "http://www.wapforum.org/DTD/wml_1.1.xml">
            <wml><card id="a" title="News"><p>Hello<br/><anchor>Next<go href="#b"/></anchor>
            <anchor>More<go href="more.wml"/></anchor></p><do type="accept" label="Back"><go href="/index.wml"/></do></card>
            <card id="b" title="Two"><p>Second card</p></card></wml>"##;
        let doc = convert_html(wml, &Url::parse("http://wap.example.org/news/index.wml").unwrap());
        assert_eq!(
            texts(&doc),
            "News\nHello|[Next->http://wap.example.org/news/index.wml] [More->http://wap.example.org/news/more.wml]\n[Back->http://wap.example.org/index.wml]\nTwo\nSecond card\n"
        );
    }

    #[test]
    fn meta_refresh_and_base() {
        let html = r#"<head><base href="http://cdn.example.net/a/"><meta http-equiv="Refresh" content="0; URL='/go/there'"></head>
            <body><a href="b.html">b</a></body>"#;
        let doc = convert_html(html, &base());
        assert_eq!(doc.refresh.as_deref(), Some("http://cdn.example.net/go/there"));
        assert_eq!(doc.links, vec!["http://cdn.example.net/a/b.html".to_string()]);
        let slow = convert_html(r#"<meta http-equiv="refresh" content="60">"#, &base());
        assert_eq!(slow.refresh, None);
    }

    #[test]
    fn pre_keeps_lines() {
        let doc = convert_html("<pre>a  b\nc</pre>", &base());
        assert_eq!(texts(&doc), "a b|c\n");
    }

    #[test]
    fn long_link_text_is_cut() {
        let long = "word ".repeat(40);
        let doc = convert_html(&format!("<a href='/x'>{long}</a>"), &base());
        let Block::Para(v) = &doc.blocks[0] else { panic!() };
        let Inline::Link { text, .. } = &v[0] else { panic!() };
        assert!(text.chars().count() <= MAX_LINK_TEXT + 1 && text.ends_with('…'), "{text}");
    }

    #[test]
    fn plain_text() {
        let doc = convert_text("line one\nline two\n\n\npara two\r\n", "notes.txt");
        assert_eq!(texts(&doc), "line one|line two\npara two\n");
    }

    #[test]
    fn wap_markup_trimmed_with_base_and_utf8_declaration() {
        let src = "\u{feff}<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE html PUBLIC \"-//WAPFORUM//DTD XHTML Mobile 1.0//EN\" \"x\">\n<html>\n  <head>\n    <title>A</title>\n  </head>\n  <body>\n    <!-- note -->\n    <p>Hola   <b>mundo</b></p>\n  </body>\n</html>\n";
        let url = Url::parse("http://m.example.org/i.xhtml").unwrap();
        let out = trim_wap_markup(src, true, &url);
        assert_eq!(
            out,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE html PUBLIC \"-//WAPFORUM//DTD XHTML Mobile 1.0//EN\" \"x\"><html><head><base href=\"http://m.example.org/i.xhtml\"/><title>A</title></head><body><p>Hola <b>mundo</b></p></body></html>"
        );
    }
}
