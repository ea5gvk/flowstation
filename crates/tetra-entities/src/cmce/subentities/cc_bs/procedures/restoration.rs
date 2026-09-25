use super::*;

impl CcBsSubentity {
    pub(in crate::cmce::subentities::cc_bs) fn fsm_on_u_call_restore(
        &mut self,
        queue: &mut MessageQueue,
        sender: TetraAddress,
        handle: u32,
        link_id: u32,
        endpoint_id: u32,
        pdu: UCallRestore,
    ) {
        let call_id = pdu.call_identifier;

        if let Some(call) = self.individual_calls.get_mut(&call_id) {
            if !call.is_active() || (sender.ssi != call.calling_addr.ssi && sender.ssi != call.called_addr.ssi) {
                self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
                return;
            }

            if call.begin_restore().is_err() {
                self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
                return;
            }
            call.active_timer_started = Some(self.dltime);
            // Only grant when the floor is free or the sender already holds it (same decision as
            // the U-TX DEMAND path). Granting while the peer is talking gives two simultaneous
            // transmitters and a stale floor_holder the UL-inactivity watchdog never ceases.
            // Duplex calls keep floor_holder = None, so they still always grant.
            //
            // Table 14.74: the bit is 0 when the MS asks to transmit and 1 when it lets the other
            // party talk. It was read the other way round: a radio asking to talk was refused and
            // one only listening was handed the floor.
            let wants_to_transmit = !pdu.request_to_transmit_send_data;
            let grant = if !call.is_simplex() {
                TransmissionGrant::Granted
            } else if !wants_to_transmit {
                if call.floor_holder.is_some() {
                    TransmissionGrant::GrantedToOtherUser
                } else {
                    TransmissionGrant::NotGranted
                }
            } else if call.floor_holder.is_none() || call.is_floor_held_by(sender.ssi) {
                if call.is_simplex() {
                    call.grant_floor(sender);
                }
                TransmissionGrant::Granted
            } else {
                TransmissionGrant::GrantedToOtherUser
            };
            call.complete_restore();
            self.send_d_call_restore(queue, sender, handle, link_id, endpoint_id, call_id, grant);
            return;
        }

        if let Some(call) = self.active_calls.get_mut(&call_id) {
            if call.begin_restore().is_err() {
                self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
                return;
            }
            // Table 14.74: bit 0 = asks to transmit, 1 = lets another member talk (see above).
            let wants_to_transmit = !pdu.request_to_transmit_send_data;
            let grant = if !wants_to_transmit {
                if call.tx_active {
                    TransmissionGrant::GrantedToOtherUser
                } else {
                    TransmissionGrant::NotGranted
                }
            } else if !call.tx_active || call.source_issi == sender.ssi {
                call.grant_floor(sender.ssi, Some(sender));
                TransmissionGrant::Granted
            } else {
                TransmissionGrant::GrantedToOtherUser
            };

            call.complete_restore();
            let floor = (grant == TransmissionGrant::Granted).then_some(GroupFloorGrant {
                call_id,
                source_issi: sender.ssi,
                dest_gssi: call.dest_gssi,
                carrier_num: call.carrier_num,
                ts: call.ts,
                is_group: true,
            });
            self.send_d_call_restore(queue, sender, handle, link_id, endpoint_id, call_id, grant);

            // A restore that hands over the floor must arm UMAC's UL-inactivity timer exactly like
            // every other grant path (see setup.rs / U-TX DEMAND): without the FloorGranted a
            // restored talker that then goes silent pins the traffic slot until the absolute call
            // time-out — forever for a duplex/Infinite call, so repeats exhaust the cell.
            if let Some(floor) = floor {
                self.send_d_tx_granted_facch(queue, call_id, floor.source_issi, floor.dest_gssi, floor.carrier_num, floor.ts);
                self.notify_floor_granted(queue, floor, true, BrewNotification::IfGroupRoutable(floor.dest_gssi));
            }
            return;
        }

        self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
    }

    fn send_d_call_restore(
        &self,
        queue: &mut MessageQueue,
        sender: TetraAddress,
        handle: u32,
        link_id: u32,
        endpoint_id: u32,
        call_id: u16,
        grant: TransmissionGrant,
    ) {
        let sdu = Self::build_d_call_restore(call_id, grant, Some(CallStatus::Callcontinue));
        let msg = Self::build_sapmsg_direct(sdu, self.dltime, sender, handle, link_id, endpoint_id);
        queue.push_back(msg);
    }

    fn reject_call_restore(
        &self,
        queue: &mut MessageQueue,
        sender: TetraAddress,
        handle: u32,
        link_id: u32,
        endpoint_id: u32,
        call_id: u16,
    ) {
        tracing::info!("CMCE: rejecting U-CALL RESTORE for unknown or inactive call_id={}", call_id);
        let sdu = Self::build_d_release(call_id, DisconnectCause::CallRestorationOfTheOtherUserFailed);
        let msg = Self::build_sapmsg_direct(sdu, self.dltime, sender, handle, link_id, endpoint_id);
        queue.push_back(msg);
    }
}
