//! Connection-mode WSP (WAP-230-WSP, clause 8.2) carried in WTP transactions: the requests a
//! terminal sends (Connect, Resume, Disconnect, Suspend, Get and the unsupported methods) and
//! the Connect Reply and Reply the gateway sends back.

use tetra_config::bluestation::WapContentTypeForm;

use crate::sndcp::wap_ip::{
    WSP_CAP_CLIENT_SDU_SIZE, WSP_CAP_SERVER_SDU_SIZE, WspConnectRequest, parse_wsp_connect_request, parse_wsp_resume_request, read_uintvar,
    write_uintvar, wsp_capability_uintvar,
};

const PDU_CONNECT: u8 = 0x01;
const PDU_CONNECT_REPLY: u8 = 0x02;
const PDU_REPLY: u8 = 0x04;
const PDU_DISCONNECT: u8 = 0x05;
const PDU_SUSPEND: u8 = 0x08;
const PDU_RESUME: u8 = 0x09;
const PDU_GET: u8 = 0x40;

/// WSP status codes (WAP-230-WSP table 36).
pub mod status {
    pub const OK: u8 = 0x20;
    pub const BAD_REQUEST: u8 = 0x40;
    pub const FORBIDDEN: u8 = 0x43;
    pub const NOT_FOUND: u8 = 0x44;
    pub const METHOD_NOT_ALLOWED: u8 = 0x45;
    pub const INTERNAL_ERROR: u8 = 0x60;
    pub const SERVICE_UNAVAILABLE: u8 = 0x63;
    pub const GATEWAY_TIMEOUT: u8 = 0x64;
}

/// WSP abort reason for a malformed PDU (WAP-230-WSP table 35), sent as a WTP user abort.
pub const ABORT_PROTOERR: u8 = 0xe0;

/// Largest header a Reply built here can carry: PDU type, status, HeadersLen and the text-form
/// Content-Type with its charset (1F 20 + 30 octets of media type + 81 EA).
pub const REPLY_OVERHEAD_MAX: usize = 3 + 34;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WspRequest<'a> {
    Connect(WspConnectRequest),
    Resume {
        session_id: usize,
    },
    Disconnect,
    Suspend,
    Get {
        uri: &'a str,
    },
    /// A method this gateway does not serve (Post, Put, Options, Head, ...): answer 405.
    Unsupported {
        pdu_type: u8,
    },
    Malformed,
}

pub(crate) fn parse_request(wsp: &[u8]) -> WspRequest<'_> {
    let Some(&pdu_type) = wsp.first() else {
        return WspRequest::Malformed;
    };
    match pdu_type {
        PDU_CONNECT => parse_wsp_connect_request(wsp)
            .map(WspRequest::Connect)
            .unwrap_or(WspRequest::Malformed),
        PDU_RESUME => parse_wsp_resume_request(wsp)
            .map(|r| WspRequest::Resume { session_id: r.session_id })
            .unwrap_or(WspRequest::Malformed),
        PDU_DISCONNECT => WspRequest::Disconnect,
        PDU_SUSPEND => WspRequest::Suspend,
        // Get, and the extended methods of the Get PDU (0x50..=0x5F).
        PDU_GET | 0x50..=0x5f => {
            let Some((len, octets)) = read_uintvar(&wsp[1..]) else {
                return WspRequest::Malformed;
            };
            let Some(uri) = wsp.get(1 + octets..1 + octets + len) else {
                return WspRequest::Malformed;
            };
            std::str::from_utf8(uri)
                .map(|uri| WspRequest::Get { uri })
                .unwrap_or(WspRequest::Malformed)
        }
        0x41..=0x4f | 0x60..=0x7f => WspRequest::Unsupported { pdu_type },
        _ => WspRequest::Malformed,
    }
}

/// Connect Reply: echo only the SDU sizes the terminal asked about, clamped to our limits.
pub(crate) fn connect_reply(session_id: u32, connect: &WspConnectRequest, max_client_sdu: usize, max_server_sdu: usize) -> Vec<u8> {
    let mut caps = Vec::new();
    for (id, max) in [(WSP_CAP_CLIENT_SDU_SIZE, max_client_sdu), (WSP_CAP_SERVER_SDU_SIZE, max_server_sdu)] {
        if let Some(requested) = wsp_capability_uintvar(connect, id) {
            let mut value = Vec::new();
            write_uintvar(requested.min(max), &mut value);
            write_uintvar(1 + value.len(), &mut caps);
            caps.push(id);
            caps.extend_from_slice(&value);
        }
    }
    let mut out = vec![PDU_CONNECT_REPLY];
    write_uintvar(session_id as usize, &mut out);
    write_uintvar(caps.len(), &mut out);
    write_uintvar(0, &mut out);
    out.extend_from_slice(&caps);
    out
}

/// The Client-SDU a Connect asked for, if any.
pub(crate) fn requested_client_sdu(connect: &WspConnectRequest) -> Option<usize> {
    wsp_capability_uintvar(connect, WSP_CAP_CLIENT_SDU_SIZE)
}

/// Reply without headers or body (the answer to a Resume).
pub fn empty_reply(status: u8) -> Vec<u8> {
    vec![PDU_REPLY, status, 0]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// application/vnd.wap.xhtml+xml (XHTML-MP), well-known value 0x45.
    Xhtml,
    /// text/vnd.wap.wml, well-known value 0x08.
    Wml,
}

/// Content-Type in the general form with a UTF-8 charset (Well-known-charset 0x81, utf-8 = 106).
fn content_type(kind: ContentKind, form: WapContentTypeForm) -> Vec<u8> {
    match (kind, form) {
        (ContentKind::Xhtml, WapContentTypeForm::Short) => vec![0x03, 0xc5, 0x81, 0xea],
        (ContentKind::Xhtml, WapContentTypeForm::Text) => {
            let media = b"application/vnd.wap.xhtml+xml\0";
            // 32 octets do not fit a Short-length (<= 30): Length-quote (0x1F) + uintvar.
            let mut out = vec![0x1f];
            write_uintvar(media.len() + 2, &mut out);
            out.extend_from_slice(media);
            out.extend_from_slice(&[0x81, 0xea]);
            out
        }
        (ContentKind::Wml, _) => vec![0x03, 0x88, 0x81, 0xea],
    }
}

pub fn reply(status: u8, kind: ContentKind, form: WapContentTypeForm, body: &[u8]) -> Vec<u8> {
    let headers = content_type(kind, form);
    let mut out = vec![PDU_REPLY, status];
    write_uintvar(headers.len(), &mut out);
    out.extend_from_slice(&headers);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sndcp::wap_ip::WspCapability;

    fn connect(client_sdu: usize, server_sdu: usize) -> WspConnectRequest {
        let uintvar = |v| {
            let mut out = Vec::new();
            write_uintvar(v, &mut out);
            out
        };
        WspConnectRequest {
            version: 0x10,
            capabilities: vec![
                WspCapability {
                    id: WSP_CAP_CLIENT_SDU_SIZE,
                    parameters: uintvar(client_sdu),
                },
                WspCapability {
                    id: WSP_CAP_SERVER_SDU_SIZE,
                    parameters: uintvar(server_sdu),
                },
            ],
        }
    }

    #[test]
    fn connect_reply_matches_spec_vector() {
        // Docs/wap-port-spec.md 7.4: both SDUs asked as 327680 and clamped to 545 (0x84 0x21).
        let reply = connect_reply(1, &connect(327_680, 327_680), 545, 545);
        assert_eq!(reply, vec![0x02, 0x01, 0x08, 0x00, 0x03, 0x80, 0x84, 0x21, 0x03, 0x81, 0x84, 0x21]);
    }

    #[test]
    fn connect_reply_sdu_negotiated() {
        // Client-SDU = min(asked, max_message_bytes), Server-SDU = min(asked, max_request_bytes).
        let reply = connect_reply(2, &connect(327_680, 327_680), 8192, 1024);
        assert_eq!(reply, vec![0x02, 0x02, 0x08, 0x00, 0x03, 0x80, 0xc0, 0x00, 0x03, 0x81, 0x88, 0x00]);
        // A terminal asking for less keeps its own value.
        let reply = connect_reply(3, &connect(300, 200), 8192, 1024);
        assert_eq!(&reply[4..], &[0x03, 0x80, 0x82, 0x2c, 0x03, 0x81, 0x81, 0x48]);
        assert_eq!(requested_client_sdu(&connect(300, 200)), Some(300));
    }

    #[test]
    fn reply_content_type_general_form_utf8() {
        let reply = reply(status::OK, ContentKind::Xhtml, WapContentTypeForm::Short, b"<p/>");
        assert_eq!(reply, [&[0x04, 0x20, 0x04, 0x03, 0xc5, 0x81, 0xea][..], b"<p/>"].concat());
        let wml = super::reply(status::NOT_FOUND, ContentKind::Wml, WapContentTypeForm::Short, b"");
        assert_eq!(wml, vec![0x04, 0x44, 0x04, 0x03, 0x88, 0x81, 0xea]);
    }

    #[test]
    fn reply_content_type_text() {
        let reply = reply(status::OK, ContentKind::Xhtml, WapContentTypeForm::Text, b"x");
        let mut expected = vec![0x04, 0x20, 34, 0x1f, 32];
        expected.extend_from_slice(b"application/vnd.wap.xhtml+xml\0");
        expected.extend_from_slice(&[0x81, 0xea, b'x']);
        assert_eq!(reply, expected);
        assert_eq!(reply.len() - 1, REPLY_OVERHEAD_MAX);
    }

    #[test]
    fn parses_requests() {
        let mut get = vec![0x40, 0x0d];
        get.extend_from_slice(b"/status.xhtml");
        get.extend_from_slice(&[0x80, 0x81]); // headers are ignored
        assert_eq!(parse_request(&get), WspRequest::Get { uri: "/status.xhtml" });
        assert_eq!(parse_request(&[0x40, 0x05, b'/']), WspRequest::Malformed);
        assert_eq!(parse_request(&[0x60, 0x01, 0x00]), WspRequest::Unsupported { pdu_type: 0x60 });
        assert_eq!(parse_request(&[0x09, 0x01, 0x00]), WspRequest::Resume { session_id: 1 });
        assert_eq!(parse_request(&[0x05, 0x01]), WspRequest::Disconnect);
        assert_eq!(parse_request(&[0x08, 0x01]), WspRequest::Suspend);
        assert_eq!(parse_request(&[]), WspRequest::Malformed);
        assert_eq!(empty_reply(status::OK), vec![0x04, 0x20, 0x00]);
    }
}
