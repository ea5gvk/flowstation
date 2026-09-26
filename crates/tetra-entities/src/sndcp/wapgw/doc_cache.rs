//! Converted documents kept in memory for their pages (`/p/doc/n`) and links (`/l/doc/k`).
//!
//! A radio only sees its own documents. Each radio keeps its last few, every document expires,
//! and the whole cache has a memory ceiling. Nothing survives a restart: an old link then gets a
//! polite "expired" page.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::convert::Document;

pub const DOCS_PER_ISSI: usize = 3;
pub const DOC_TTL: Duration = Duration::from_secs(15 * 60);
pub const MAX_CACHE_BYTES: usize = 2 * 1024 * 1024;

pub struct StoredDoc {
    pub id: u32,
    pub issi: u32,
    pub doc: Document,
    bytes: usize,
    stored: Instant,
}

pub struct DocCache {
    docs: VecDeque<StoredDoc>,
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
            next_id: 1,
            per_issi: per_issi.max(1),
            ttl,
            max_bytes,
        }
    }

    fn expire(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.docs.retain(|d| now.duration_since(d.stored) < ttl);
    }

    fn bytes(&self) -> usize {
        self.docs.iter().map(|d| d.bytes).sum()
    }

    /// Keep `doc` for `issi`; returns its id.
    pub fn insert(&mut self, issi: u32, doc: Document, now: Instant) -> u32 {
        self.expire(now);
        let id = self.next_id;
        // Small ids keep the page links short; wrap well before they get long.
        self.next_id = if self.next_id >= 99_999 { 1 } else { self.next_id + 1 };
        self.docs.retain(|d| d.id != id);
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
        let ids: Vec<u32> = (0..4).map(|i| cache.insert(1, doc(&format!("d{i}")), t0)).collect();
        let other = cache.insert(2, doc("other"), t0);
        assert!(cache.get(1, ids[0], t0).is_none(), "oldest of ISSI 1 evicted");
        for &id in &ids[1..] {
            assert!(cache.get(1, id, t0).is_some());
        }
        assert!(cache.get(1, other, t0).is_none(), "another radio's document");
        assert_eq!(cache.get(2, other, t0).unwrap().doc.title, "other");

        // Memory ceiling: the oldest documents go first.
        let mut small = DocCache::new(10, DOC_TTL, 5000);
        let big = |c: char| doc(&c.to_string().repeat(1000));
        let a = small.insert(1, big('a'), t0);
        let b = small.insert(1, big('b'), t0);
        let c = small.insert(1, big('c'), t0);
        assert!(small.get(1, a, t0).is_none());
        assert!(small.get(1, b, t0).is_some() && small.get(1, c, t0).is_some());
    }

    #[test]
    fn doc_cache_ttl() {
        let mut cache = DocCache::default();
        let t0 = Instant::now();
        let id = cache.insert(1, doc("x"), t0);
        assert!(cache.get(1, id, t0 + DOC_TTL - Duration::from_secs(1)).is_some());
        assert!(cache.get(1, id, t0 + DOC_TTL).is_none());
        assert_eq!(cache.len(), 0);
    }
}
