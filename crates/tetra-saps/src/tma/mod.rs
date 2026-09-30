use tetra_core::{BitBuffer, EndpointId, LinkId, TetraAddress, Todo, TxReporter};

use crate::lcmc::fields::chan_alloc_req::CmceChanAllocReq;

/// Clause 20.4.1.1.1
/// TMA-CANCEL request: this primitive shall be used to cancel a TMA-UNITDATA
/// request primitive that was submitted by the LLC.
#[derive(Debug, Clone)]
pub struct TmaCancelReq {
    pub req_handle: Todo,
}

/// Clause 20.4.1.1.2
/// TMA-RELEASE indication: this primitive may be used when the MAC leaves a
/// channel in order to indicate that the connection on that channel is lost
/// (e.g. to indicate local disconnection of any advanced links on that channel).
#[derive(Debug, Clone)]
pub struct TmaReleaseInd {
    pub endpoint_id: EndpointId,
}

/// Clause 22.3.3.1.1 gives some hints on reports in the MS context
#[derive(Debug, Clone)]
pub enum TmaReport {
    /// Confirm handle to the request
    ConfirmHandle,
    /// MS only. Successful complete transmission by random access
    SuccessRandomAccess,
    /// MS only. Complete transmission by reserved access or stealing
    SuccessReservedOrStealing,

    FailedTransfer,
    FragmentationFailure,
    /// MS only
    RandomAccessFailure,
}

/// Clause 20.4.1.1.3
/// TMA-REPORT indication: this primitive shall be used by the MAC to report
/// on the progress or failure of a request procedure. The result of the
/// transfer shall be passed as a report parameter.
#[derive(Debug, Clone)]
pub struct TmaReportInd {
    pub req_handle: Todo,
    pub report: TmaReport,
}

/// `TmaUnitdataReq::data_category` of a packet-data TM-SDU (an SNDCP datagram): the MAC lets
/// signalling that fits whole go before its fragments (clause 20.2.4.13 leaves the values to the
/// implementer).
pub const DATA_CATEGORY_PACKET_DATA: Todo = 1;

/// `TmaUnitdataReq::data_category` of SNDCP signalling that carries a packet-data channel
/// assignment (or the quit back to the MCCH): the MAC checks, when it sends it, that the channel
/// it gives is still its radio's, which a call or a release may have changed while it waited.
pub const DATA_CATEGORY_PDCH_ASSIGNMENT: Todo = 2;

/// `TmaUnitdataReq::data_category` of an advanced link segment that asks for an acknowledgement,
/// on a packet-data channel of several slots: the MAC reserves the radio an uplink slot for its
/// answer and grants it with the segment (EN 300 392-2 23.5.1.3.3, 23.5.2.2.1 b).
pub const DATA_CATEGORY_AL_REPLY: Todo = 3;

/// Clause 20.4.1.1.4
/// TMA-UNITDATA request: this primitive shall be used to request the MAC to
/// transmit a TM-SDU.
#[derive(Debug, Clone)]
pub struct TmaUnitdataReq {
    /// Preferred carrier for BS-internal routing. Legacy MCCH signalling may leave this unset.
    pub carrier_num: Option<u16>,
    pub req_handle: Todo,
    pub pdu: BitBuffer,
    pub main_address: TetraAddress,
    // pub scrambling_code: u32, // TODO FIXME : according to the spec, should be there, but why do we need to provide this?
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    // pub pdu_prio: Todo, // optional feature
    pub stealing_permission: bool,
    pub subscriber_class: Todo,
    pub air_interface_encryption: Option<Todo>,
    pub stealing_repeats_flag: Option<bool>,
    pub data_category: Option<Todo>,

    // Custom fields for BS stack:
    /// Optional Channel Allocation Request that may be included by CMCE
    pub chan_alloc: Option<CmceChanAllocReq>,
    pub tx_reporter: Option<TxReporter>,
}

/// Clause 20.4.1.1.4
/// TMA-UNITDATA indication: this primitive shall be used by the MAC to deliver
/// a received TM-SDU. This primitive may also be used with no TM-SDU if the
/// MAC needs to inform the higher layers of a channel allocation received
/// without an associated TM-SDU.
#[derive(Debug, Clone)]
pub struct TmaUnitdataInd {
    /// Carrier on which this TM-SDU was received.
    pub carrier_num: u16,
    pub pdu: Option<BitBuffer>,
    pub main_address: TetraAddress,
    pub scrambling_code: u32,
    pub link_id: LinkId,
    pub endpoint_id: EndpointId,
    pub new_endpoint_id: Option<EndpointId>,
    pub css_endpoint_id: Option<EndpointId>,
    pub air_interface_encryption: Todo,
    pub chan_change_response_req: bool,
    pub chan_change_handle: Option<Todo>,
    pub chan_info: Option<Todo>,
}
