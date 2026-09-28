//! Interface to the Internet side of the gateway.
//!
//! The gateway runs on the TETRA stack thread and never blocks: it hands a [`FetchRequest`] to a
//! [`Fetcher`] and collects the finished [`FetchReply`] on a later tick. A real fetcher (download,
//! HTML conversion, pagination, document cache) runs on its own threads ([`super::fetch`]); the
//! one here only says that browsing is not available.

use std::collections::VecDeque;

use super::home;
use super::wsp::{ContentKind, status};

/// What a request asks the Internet side for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchTarget {
    /// A web page (absolute http/https URL).
    Url(String),
    /// A search query for the configured search engine.
    Search(String),
    /// A gateway document path (page of a converted document `/p/...`, shortened link `/l/...`),
    /// with its query.
    Doc(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub id: u64,
    pub issi: u32,
    pub target: FetchTarget,
    /// Largest body the reply may carry.
    pub budget: usize,
    /// Absolute URL of the gateway home page, for the links back home.
    pub home: String,
    /// The page the link was on (its Referer), fetched again when the link's document is no
    /// longer known.
    pub back: Option<FetchTarget>,
}

/// A page ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub status: u8,
    pub kind: ContentKind,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchReply {
    pub id: u64,
    pub page: Page,
    /// Host the page came from (after redirects), for the dashboard; never the full URL.
    pub domain: Option<String>,
}

pub trait Fetcher: Send {
    /// Queue a request without blocking; gives it back when the queue is full.
    fn submit(&mut self, req: FetchRequest) -> Result<(), FetchRequest>;
    /// A finished request, if any, without blocking.
    fn try_recv(&mut self) -> Option<FetchReply>;
}

/// Fetcher for builds without Internet access: every request gets a "not available" page.
#[derive(Default)]
pub struct UnavailableFetcher {
    ready: VecDeque<FetchReply>,
}

impl Fetcher for UnavailableFetcher {
    fn submit(&mut self, req: FetchRequest) -> Result<(), FetchRequest> {
        let body = home::notice_page(
            "Sin Internet",
            "La navegación no está disponible en esta estación.",
            &req.home,
            req.budget,
        );
        self.ready.push_back(FetchReply {
            id: req.id,
            page: Page {
                status: status::SERVICE_UNAVAILABLE,
                kind: ContentKind::Xhtml,
                body: body.into_bytes(),
            },
            domain: None,
        });
        Ok(())
    }

    fn try_recv(&mut self) -> Option<FetchReply> {
        self.ready.pop_front()
    }
}
