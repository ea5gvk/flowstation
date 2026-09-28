//! Converted documents kept in memory for their pages (`/p/doc/n`) and links (`/l/doc/k`).
//!
//! A radio only sees its own documents. Each radio keeps its last few, every document expires,
//! and the whole cache has a memory ceiling. What a document was fetched from and where its links
//! go outlive it in a small index, which a persistent cache also keeps in a file: an old link
//! (after the expiry or a restart) fetches its target again instead of dead-ending.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::convert::Document;

pub const DOCS_PER_ISSI: usize = 3;
pub const DOC_TTL: Duration = Duration::from_secs(60 * 60);
pub const MAX_CACHE_BYTES: usize = 2 * 1024 * 1024;
/// Documents whose source and links are remembered after they expire.
pub const INDEX_LEN: usize = 64;

/// What is left of a document once it has expired: where it came from and where its links go.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocIndex {
    pub id: u32,
    pub issi: u32,
    pub source: String,
    pub links: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct SavedIndex {
    next_id: u32,
    index: Vec<DocIndex>,
}

pub struct StoredDoc {
    pub id: u32,
    pub issi: u32,
    pub doc: Document,
    bytes: usize,
    stored: Instant,
}

pub struct DocCache {
    docs: VecDeque<StoredDoc>,
    index: VecDeque<DocIndex>,
    /// File the index is kept in, for a cache that outlives a restart.
    path: Option<PathBuf>,
    next_id: u32,
    per_issi: usize,
    ttl: Duration,
    max_bytes: usize,
}

impl Default for DocCache {
    fn default() -> Self {
        Self::new(DOCS_PER_ISSI, DOC_TTL, MAX_CACHE_BYTES)
    }
}

impl DocCache {
    pub fn new(per_issi: usize, ttl: Duration, max_bytes: usize) -> Self {
        Self {
            docs: VecDeque::new(),
            index: VecDeque::new(),
            path: None,
            next_id: 1,
            per_issi: per_issi.max(1),
            ttl,
            max_bytes,
        }
    }

    /// A cache whose index is kept in `path` (loaded now, rewritten on every new document).
    pub fn persistent(path: PathBuf) -> Self {
        let mut cache = Self::default();
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(saved) = serde_json::from_str::<SavedIndex>(&text)
        {
            cache.next_id = saved.next_id.clamp(1, 99_999);
            cache.index = saved.index.into();
        }
        cache.path = Some(path);
        cache
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let saved = SavedIndex {
            next_id: self.next_id,
            index: self.index.iter().cloned().collect(),
        };
        let tmp = path.with_extension("tmp");
        let written = serde_json::to_vec(&saved)
            .map_err(std::io::Error::other)
            .and_then(|bytes| std::fs::write(&tmp, bytes))
            .and_then(|()| std::fs::rename(&tmp, path));
        if let Err(e) = written {
            tracing::debug!("WAP: could not save the document index to {}: {}", path.display(), e);
        }
    }

    fn expire(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.docs.retain(|d| now.duration_since(d.stored) < ttl);
    }

    fn bytes(&self) -> usize {
        self.docs.iter().map(|d| d.bytes).sum()
    }

    /// Keep `doc`, fetched from `source`, for `issi`; returns its id.
    pub fn insert(&mut self, issi: u32, doc: Document, source: &str, now: Instant) -> u32 {
        self.expire(now);
        let id = self.next_id;
        // Small ids keep the page links short; wrap well before they get long.
        self.next_id = if self.next_id >= 99_999 { 1 } else { self.next_id + 1 };
        self.docs.retain(|d| d.id != id);
        self.index.retain(|i| i.id != id);
        self.index.push_back(DocIndex {
            id,
            issi,
            source: source.to_string(),
            links: doc.links.clone(),
        });
        while self.index.len() > INDEX_LEN {
            self.index.pop_front();
        }
        self.save();
        let bytes = doc.approx_bytes();
        self.docs.push_back(StoredDoc {
            id,
            issi,
            doc,
            bytes,
            stored: now,
        });
        while self.docs.iter().filter(|d| d.issi == issi).count() > self.per_issi {
            let oldest = self.docs.iter().position(|d| d.issi == issi).expect("counted above");
            self.docs.remove(oldest);
        }
        while self.bytes() > self.max_bytes && self.docs.len() > 1 {
            self.docs.pop_front();
        }
        id
    }

    /// Document `id` if it belongs to `issi` and has not expired.
    pub fn get(&mut self, issi: u32, id: u32, now: Instant) -> Option<&StoredDoc> {
        self.expire(now);
        self.docs.iter().find(|d| d.id == id && d.issi == issi)
    }

    /// Source and links of document `id` of `issi`, also after the document itself has expired.
    pub fn recall(&self, issi: u32, id: u32) -> Option<&DocIndex> {
        self.index.iter().rev().find(|i| i.id == id && i.issi == issi)
    }

    /// The newest document of `issi`.
    pub fn latest(&self, issi: u32) -> Option<&StoredDoc> {
        self.docs.iter().rev().find(|d| d.issi == issi)
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sndcp::wapgw::convert::{Block, Inline};

    fn doc(text: &str) -> Document {
        Document {
            title: text.to_string(),
            blocks: vec![Block::Para(vec![Inline::Text(text.to_string())])],
            ..Default::default()
        }
    }

    #[test]
    fn doc_cache_evicts() {
        let mut cache = DocCache::default();
        let t0 = Instant::now();
        let ids: Vec<u32> = (0..4)
            .map(|i| cache.insert(1, doc(&format!("d{i}")), "http://example.com/", t0))
            .collect();
        let other = cache.insert(2, doc("other"), "http://example.com/", t0);
        assert!(cache.get(1, ids[0], t0).is_none(), "oldest of ISSI 1 evicted");
        for &id in &ids[1..] {
            assert!(cache.get(1, id, t0).is_some());
        }
        assert!(cache.get(1, other, t0).is_none(), "another radio's document");
        assert_eq!(cache.get(2, other, t0).unwrap().doc.title, "other");

        // Memory ceiling: the oldest documents go first.
        let mut small = DocCache::new(10, DOC_TTL, 5000);
        let big = |c: char| doc(&c.to_string().repeat(1000));
        let a = small.insert(1, big('a'), "http://example.com/", t0);
        let b = small.insert(1, big('b'), "http://example.com/", t0);
        let c = small.insert(1, big('c'), "http://example.com/", t0);
        assert!(small.get(1, a, t0).is_none());
        assert!(small.get(1, b, t0).is_some() && small.get(1, c, t0).is_some());
    }

    #[test]
    fn doc_cache_ttl() {
        let mut cache = DocCache::default();
        let t0 = Instant::now();
        let id = cache.insert(1, doc("x"), "http://example.com/", t0);
        assert!(cache.get(1, id, t0 + DOC_TTL - Duration::from_secs(1)).is_some());
        assert!(cache.get(1, id, t0 + DOC_TTL).is_none());
        assert_eq!(cache.len(), 0);
    }

    /// The index outlives the document: its source and links are still known after the expiry,
    /// and a persistent cache brings them (and the id counter) back after a restart.
    #[test]
    fn doc_index_outlives_the_document_and_a_restart() {
        let path = std::env::temp_dir().join(format!("flowstation-wap-docs-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let t0 = Instant::now();
        let mut linked = doc("x");
        linked.links = vec!["http://example.com/a".to_string(), "http://example.com/b".to_string()];

        let mut cache = DocCache::persistent(path.clone());
        let id = cache.insert(1, linked, "http://example.com/", t0);
        assert!(cache.get(1, id, t0 + DOC_TTL).is_none(), "the document itself expires");
        let recalled = cache.recall(1, id).expect("its index stays");
        assert_eq!(
            (recalled.source.as_str(), recalled.links[1].as_str()),
            ("http://example.com/", "http://example.com/b")
        );
        assert!(cache.recall(2, id).is_none(), "another radio's index");

        let restarted = DocCache::persistent(path.clone());
        assert_eq!(restarted.recall(1, id).map(|i| i.links.len()), Some(2));
        assert_eq!(restarted.next_id, id + 1, "new documents do not reuse the old ids");
        let _ = std::fs::remove_file(&path);
    }
}
