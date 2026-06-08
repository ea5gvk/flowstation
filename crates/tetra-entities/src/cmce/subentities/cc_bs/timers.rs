use super::*;
use crate::net_telemetry::TelemetryEvent;

impl CcBsSubentity {
    pub fn tick_start_with_events(&mut self, queue: &mut MessageQueue, dltime: TdmaTime) -> Vec<TelemetryEvent> {
        // Snapshot before tick so we can detect changes
        let calls_before: std::collections::HashSet<u16> = self.active_calls.keys().copied().collect();
        let ind_before: std::collections::HashSet<u16> = self.individual_calls.keys().copied().collect();

        self.tick_start(queue, dltime);

        // Emit events for ended calls
        let mut events = Vec::new();
        for id in calls_before.iter() {
            if !self.active_calls.contains_key(id) {
                events.push(TelemetryEvent::GroupCallEnded { call_id: *id, gssi: 0 });
            }
        }
        for id in ind_before.iter() {
            if !self.individual_calls.contains_key(id) {
                events.push(TelemetryEvent::IndividualCallEnded { call_id: *id });
            }
        }
        events
    }

    pub fn tick_start(&mut self, queue: &mut MessageQueue, dltime: TdmaTime) {
        self.dltime = dltime;

        // ETSI T310 equivalent for active calls.
        self.check_call_timeout_expiry(queue);
        // ETSI T301/T302 equivalent while waiting for call completion.
        self.check_individual_setup_timeout(queue);
        // Check hangtime expiry for active local calls
        self.check_hangtime_expiry(queue);

        if let Some(tasks) = self.circuits.tick_start(dltime) {
            for task in tasks {
                match task {
                    CircuitMgrCmd::SendDSetup(call_id, usage, ts) => {
                        // Peek at routing info first (immutable) so the EE gate — a `&self` method —
                        // can run before we take the mutable borrow on the cached D-SETUP below.
                        let (dest_addr, is_individual, resend) = match self.cached_setups.get(&call_id) {
                            Some(c) => (c.dest_addr, c.is_individual, c.resend),
                            None => {
                                tracing::trace!(
                                    "CMCE: skipping D-SETUP resend for call_id={} (no cached D-SETUP; likely Brew-routed individual call)",
                                    call_id
                                );
                                continue;
                            }
                        };
                        if !resend {
                            continue;
                        }
                        // Energy-Economy gate (clause 16.7): hold an individual-call D-SETUP resend
                        // until the called MS's downlink monitoring window opens, so the page lands
                        // when the radio is actually listening. The bounded fallback inside
                        // `ee_dsetup_blocks` reverts to the blind resend after EE_DSETUP_FALLBACK_TS,
                        // so a wrong granted window phase is never worse than the historical behaviour.
                        if is_individual && self.ee_dsetup_blocks(call_id, dest_addr.ssi) {
                            tracing::debug!(
                                "EE: holding D-SETUP resend for {} (call_id {}) until its monitoring window",
                                dest_addr.ssi, call_id
                            );
                            continue;
                        }
                        // Now take the mutable borrow to apply the late-entry grant tweak and serialize.
                        let cached = self
                            .cached_setups
                            .get_mut(&call_id)
                            .expect("cached D-SETUP present (peeked above)");
                        // Late-entry D-SETUP keeps listeners attached to an established group call.
                        // During hangtime there is no current speaker, but sending NotGranted makes
                        // some terminals treat PTT as denied. Keep them in listener state and allow
                        // floor requests via D-TX-CEASED/TRP=0.
                        if self.active_calls.contains_key(&call_id) {
                            cached.pdu.transmission_grant = TransmissionGrant::GrantedToOtherUser;
                            cached.pdu.transmission_request_permission = false;
                        }
                        if is_individual {
                            // P2P individual call in setup phase: resend DSetup on MCCH
                            // (no chan_alloc, no circuit open yet). The called MS may be
                            // sleeping (EE) and will receive it at its next monitoring window.
                            let mut sdu = BitBuffer::new_autoexpand(80);
                            cached.pdu.to_bitbuf(&mut sdu).expect("Failed to serialize DSetup");
                            sdu.seek(0);
                            let prim = Self::build_sapmsg(sdu, None, dest_addr, Layer2Service::Unacknowledged, None);
                            queue.push_back(prim);
                        } else {
                            let (sdu, chan_alloc) = Self::build_d_setup_prim(&cached.pdu, usage, ts, UlDlAssignment::Both);
                            let prim = Self::build_sapmsg(sdu, Some(chan_alloc), dest_addr, Layer2Service::Unacknowledged, None);
                            queue.push_back(prim);
                        }
                    }

                    CircuitMgrCmd::SendClose(call_id, circuit) => {
                        // Circuit expiry safety net: circuit_mgr detected a stale open circuit
                        // that CMCE forgot to close (e.g. MS lost coverage without disconnecting).
                        // Force cleanup unconditionally — release D-RELEASE, close circuit, free TS.
                        tracing::warn!(
                            "CMCE: force-closing stale circuit call_id={} ts={} (circuit expiry)",
                            call_id, circuit.ts
                        );
                        let ts = circuit.ts;
                        // Get our cached D-SETUP, build D-RELEASE and send
                        if let Some(cached) = self.cached_setups.get(&call_id) {
                            let sdu = Self::build_d_release_from_d_setup(&cached.pdu, DisconnectCause::ExpiryOfTimer);
                            let prim = Self::build_sapmsg(sdu, None, cached.dest_addr, Layer2Service::Unacknowledged, None);
                            queue.push_back(prim);

                            if let Some(ind_call) = self.individual_calls.get(&call_id) {
                                if !ind_call.calling_over_brew {
                                    let sdu_calling = Self::build_d_release_from_d_setup(&cached.pdu, DisconnectCause::ExpiryOfTimer);
                                    let prim_calling = SapMsg {
                                        sap: Sap::LcmcSap,
                                        src: TetraEntity::Cmce,
                                        dest: TetraEntity::Mle,
                                        msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                                            sdu: sdu_calling,
                                            handle: ind_call.calling_handle,
                                            endpoint_id: ind_call.calling_endpoint_id,
                                            link_id: ind_call.calling_link_id,
                                            layer2service: Layer2Service::Unacknowledged,
                                            pdu_prio: 0,
                                            layer2_qos: 0,
                                            stealing_permission: false,
                                            stealing_repeats_flag: false,
                                            chan_alloc: None,
                                            main_address: ind_call.calling_addr,
                                            tx_reporter: None,
                                        }),
                                    };
                                    queue.push_back(prim_calling);
                                }
                            }
                        } else {
                            tracing::warn!("No cached D-SETUP for call id {} during timer-close", call_id);
                            if let Some(ind_call) = self.individual_calls.get(&call_id) {
                                if !ind_call.calling_over_brew {
                                    let sdu_calling = Self::build_d_release(call_id, DisconnectCause::ExpiryOfTimer);
                                    let prim_calling = if ind_call.is_active() {
                                        Self::build_sapmsg_stealing(
                                            sdu_calling,
                                            ind_call.calling_addr,
                                            ind_call.calling_ts,
                                            Some(ind_call.calling_usage),
                                        )
                                    } else {
                                        Self::build_sapmsg_direct(
                                            sdu_calling,
                                            ind_call.calling_addr,
                                            ind_call.calling_handle,
                                            ind_call.calling_link_id,
                                            ind_call.calling_endpoint_id,
                                        )
                                    };
                                    queue.push_back(prim_calling);
                                } else if !ind_call.called_over_brew {
                                    let sdu_called = Self::build_d_release(call_id, DisconnectCause::ExpiryOfTimer);
                                    let prim_called = if ind_call.is_active() {
                                        Self::build_sapmsg_stealing(
                                            sdu_called,
                                            ind_call.called_addr,
                                            ind_call.called_ts,
                                            Some(ind_call.called_usage),
                                        )
                                    } else if let (Some(handle), Some(link_id), Some(endpoint_id)) =
                                        (ind_call.called_handle, ind_call.called_link_id, ind_call.called_endpoint_id)
                                    {
                                        Self::build_sapmsg_direct(
                                            sdu_called,
                                            ind_call.called_addr,
                                            handle,
                                            link_id,
                                            endpoint_id,
                                        )
                                    } else {
                                        Self::build_sapmsg(sdu_called, None, ind_call.called_addr, Layer2Service::Unacknowledged, None)
                                    };
                                    queue.push_back(prim_called);
                                }
                            }
                        }

                        if let Some(ind_call) = self.individual_calls.get(&call_id) {
                            if (ind_call.called_over_brew || ind_call.calling_over_brew)
                                && let Some(brew_uuid) = ind_call.brew_uuid
                            {
                                queue.push_back(SapMsg {
                                    sap: Sap::Control,
                                    src: TetraEntity::Cmce,
                                    dest: TetraEntity::Brew,
                                    msg: SapMsgInner::CmceCallControl(CallControl::NetworkCircuitRelease {
                                        brew_uuid,
                                        cause: DisconnectCause::ExpiryOfTimer.into_raw() as u8,
                                    }),
                                });
                            }
                        }

                        // Capture peer_ts before removing individual_calls (duplex P2P has two TS).
                        let peer_ts = self.individual_calls.get(&call_id).and_then(|ind| {
                            if ind.called_ts != ind.calling_ts { Some(ind.called_ts) } else { None }
                        });

                        // Clean up call state
                        self.cached_setups.remove(&call_id);
                        self.active_calls.remove(&call_id);
                        self.individual_calls.remove(&call_id);

                        // Signal UMAC to release the circuit
                        Self::signal_umac_circuit_close(queue, circuit);
                        self.release_timeslot(ts);

                        // For duplex P2P the call has two timeslots. The peer circuit will get
                        // its own SendClose from circuit_mgr, but individual_calls is already
                        // gone by then so its timeslot allocator entry would leak. Release it now.
                        if let Some(p_ts) = peer_ts {
                            if p_ts != ts {
                                self.release_timeslot(p_ts);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Energy-Economy monitoring-window gate for an individual-call D-SETUP resend (clause 16.7).
    ///
    /// Returns `true` when the called MS (`dest_ssi`) is under Energy Economy and its downlink
    /// monitoring window is currently closed, so the resend should be held until the window opens.
    /// Returns `false` — i.e. send now — when the MS is not in EE (absent from the published map),
    /// when its window is open, or once setup has been pending longer than `EE_DSETUP_FALLBACK_TS`
    /// (the bounded fallback: a wrong granted window phase degrades to the historical blind resend
    /// rather than blocking setup until it times out unanswered).
    fn ee_dsetup_blocks(&self, call_id: u16, dest_ssi: u32) -> bool {
        let window_closed = {
            let state = self.config.state_read();
            match state.ee_monitoring_windows.get(&dest_ssi) {
                Some(&(frame, mframe, cycle_len)) => {
                    !self.dltime.in_ee_monitoring_window(frame, mframe, cycle_len)
                }
                None => false, // not in energy economy — always reachable
            }
        };
        if !window_closed {
            return false;
        }
        // Bounded fallback: stop holding once setup has been pending too long.
        match self.individual_calls.get(&call_id).and_then(|c| c.setup_timer_started) {
            Some(started) => started.age(self.dltime) < EE_DSETUP_FALLBACK_TS,
            None => false, // no setup clock to bound the wait — don't gate
        }
    }

    /// Release active calls when their configured call timeout expires.
    pub(super) fn check_call_timeout_expiry(&mut self, queue: &mut MessageQueue) {
        let expired_group_calls: Vec<u16> = self
            .active_calls
            .iter()
            .filter_map(|(&call_id, call)| call.call_timeout_expired(self.dltime).then_some(call_id))
            .collect();

        for call_id in expired_group_calls {
            tracing::info!("Call timeout expired for group call_id={}, releasing", call_id);
            self.release_group_call(queue, call_id, DisconnectCause::UserRequestedDisconnection);
        }

        let expired_individual_calls: Vec<u16> = self
            .individual_calls
            .iter()
            .filter_map(|(&call_id, call)| call.active_timeout_expired(self.dltime).then_some(call_id))
            .collect();

        for call_id in expired_individual_calls {
            tracing::info!("Call timeout expired for individual call_id={}, releasing", call_id);
            self.release_individual_call(queue, call_id, DisconnectCause::ExpiryOfTimer);
        }
    }

    /// Release individual setup attempts that exceed setup timeout.
    pub(super) fn check_individual_setup_timeout(&mut self, queue: &mut MessageQueue) {
        let expired_setup_calls: Vec<u16> = self
            .individual_calls
            .iter()
            .filter_map(|(&call_id, call)| call.setup_timeout_expired(self.dltime).then_some(call_id))
            .collect();

        for call_id in expired_setup_calls {
            tracing::info!("Setup timeout expired for individual call_id={}, releasing", call_id);
            self.release_individual_call(queue, call_id, DisconnectCause::ExpiryOfTimer);
        }

        // EE DSetup retry: for P2P individual calls still in CallSetupPending state
        // (called MS has not yet sent U-ALERT), periodically retransmit DSetup on MCCH
        // so that a sleeping MS can receive it at its next monitoring window.
        // Retry interval ~2.5 s (180 timeslots; one slot = 170/12 ms, ~72 slots/s). Frequent enough
        // that a retry instant has a good chance of coinciding with the called MS's EE monitoring
        // window (the ee_dsetup_blocks gate below only lets a retry through when that window is open),
        // yet bounded so we never flood the MS before the 60 s setup timeout.
        // NOTE: TdmaTime::age()/diff() return TIMESLOTS (not frames) — locals are named accordingly.
        const DSETUP_RETRY_INTERVAL_TS: i32 = 180; // ~2.5 s
        let retry_calls: Vec<u16> = self
            .individual_calls
            .iter()
            .filter_map(|(&call_id, call)| {
                if call.state != IndividualCallState::CallSetupPending {
                    return None;
                }
                let Some(started) = call.setup_timer_started else { return None; };
                let age_ts = started.age(self.dltime);
                // First retry after ~0.25 s, then every ~2.5 s.
                if age_ts >= 18 && age_ts % DSETUP_RETRY_INTERVAL_TS == 0 {
                    Some(call_id)
                } else {
                    None
                }
            })
            .collect();

        for call_id in retry_calls {
            let Some(cached) = self.cached_setups.get(&call_id) else { continue; };
            if !cached.is_individual { continue; }
            let dest_addr = cached.dest_addr;
            // Same Energy-Economy monitoring-window gate as the circuit_mgr resend path: while the
            // called MS's window is closed, hold this retry (the bounded fallback inside
            // `ee_dsetup_blocks` resumes it if the granted window phase turns out wrong). This is
            // what actually aligns the retry to the MS's wake window instead of blind 10 s spamming.
            if self.ee_dsetup_blocks(call_id, dest_addr.ssi) {
                tracing::debug!(
                    "EE: holding D-SETUP setup-retry for {} (call_id {}) until its monitoring window",
                    dest_addr.ssi, call_id
                );
                continue;
            }
            let mut sdu = BitBuffer::new_autoexpand(80);
            if cached.pdu.to_bitbuf(&mut sdu).is_err() { continue; }
            sdu.seek(0);
            let prim = Self::build_sapmsg(sdu, None, dest_addr, Layer2Service::Unacknowledged, None);
            tracing::debug!(
                "EE DSetup retry for call_id={} to ISSI {} (setup pending, MS reachable)",
                call_id, dest_addr.ssi
            );
            queue.push_back(prim);
        }
    }

    /// Check if any active calls in NoActiveSpeaker (hangtime) have expired and release them.
    pub(super) fn check_hangtime_expiry(&mut self, queue: &mut MessageQueue) {
        // Hangtime in TDMA timeslots: hangtime_secs * frames_per_sec * timeslots_per_frame
        // TETRA: 18 frames/multiframe, 4 timeslots/frame → 72 timeslots/second
        let hangtime_secs = self.config.config().cell.hangtime_secs as i32;
        let hangtime_frames: i32 = hangtime_secs * 18 * 4;

        let expired: Vec<u16> = self
            .active_calls
            .iter()
            .filter_map(|(&call_id, call)| match call.state() {
                GroupCallState::NoActiveSpeaker { since } if since.age(self.dltime) > hangtime_frames => Some(call_id),
                _ => None,
            })
            .collect();

        for call_id in expired {
            tracing::info!("Hangtime expired for call_id={}, releasing", call_id);
            self.release_group_call(queue, call_id, DisconnectCause::UserRequestedDisconnection);
        }
    }

    /// Handle UL inactivity timeout: force TX ceased for the transmitting MS on the given timeslot.
    /// Called when UMAC detects no voice frames on a traffic channel (UL side) for the timeout period.
    /// Corresponds to BS-side T323 expiry (ETSI EN 300 392-2 §14.9.2).
    pub(super) fn handle_ul_inactivity_timeout(&mut self, queue: &mut MessageQueue, ts: u8) {
        // Check individual (P2P simplex) calls first — they were not checked before,
        // causing UL inactivity to silently drop frames without forcing TX-CEASED on the radio.
        let individual_call_id = self.individual_calls
            .iter()
            .find(|(_, call)| {
                call.is_active()
                    && !call.simplex_duplex
                    && call.floor_holder.is_some()
                    && {
                        // Only trigger if the inactivity is on the floor holder's TS,
                        // not on the listening party's TS (which is expected to be silent).
                        let holder_ssi = call.floor_holder.unwrap();
                        let holder_ts = if holder_ssi == call.calling_addr.ssi {
                            call.calling_ts
                        } else {
                            call.called_ts
                        };
                        holder_ts == ts
                    }
            })
            .map(|(id, _)| *id);

        if let Some(call_id) = individual_call_id {
            let call = self.individual_calls.get_mut(&call_id).unwrap();
            let floor_holder_ssi = call.floor_holder.take(); // clear floor holder
            let Some(holder_ssi) = floor_holder_ssi else { return; };

            let (holder_addr, holder_ts, holder_usage, peer_addr, peer_ts, peer_usage) =
                if holder_ssi == call.calling_addr.ssi {
                    (call.calling_addr, call.calling_ts, call.calling_usage,
                     call.called_addr,  call.called_ts,  call.called_usage)
                } else {
                    (call.called_addr,  call.called_ts,  call.called_usage,
                     call.calling_addr, call.calling_ts, call.calling_usage)
                };

            tracing::warn!(
                "UL inactivity timeout on ts={} for individual call_id={}, forcing TX-CEASED on ISSI {} and granting floor to peer ISSI {}",
                ts, call_id, holder_ssi, peer_addr.ssi
            );

            // D-TX-CEASED to floor holder — confirms floor released.
            let ceased_pdu = DTxCeased {
                call_identifier: call_id,
                transmission_request_permission: false,
                notification_indicator: None,
                facility: None,
                dm_ms_address: None,
                proprietary: None,
            };
            let mut ceased_sdu = BitBuffer::new_autoexpand(30);
            ceased_pdu.to_bitbuf(&mut ceased_sdu).expect("serialize DTxCeased");
            ceased_sdu.seek(0);
            let ceased_msg = Self::build_sapmsg_stealing_ul_dl(ceased_sdu, holder_addr, holder_ts, Some(holder_usage), UlDlAssignment::Dl);
            queue.push_back(ceased_msg);

            // D-TX-GRANTED(Granted) to peer — they can now take the floor.
            let granted_pdu = DTxGranted {
                call_identifier: call_id,
                transmission_grant: TransmissionGrant::Granted.into_raw() as u8,
                transmission_request_permission: false,
                encryption_control: false,
                reserved: false,
                notification_indicator: None,
                transmitting_party_type_identifier: Some(1),
                transmitting_party_address_ssi: Some(peer_addr.ssi as u64),
                transmitting_party_extension: None,
                external_subscriber_number: None,
                facility: None,
                dm_ms_address: None,
                proprietary: None,
            };
            let mut granted_sdu = BitBuffer::new_autoexpand(50);
            granted_pdu.to_bitbuf(&mut granted_sdu).expect("serialize DTxGranted");
            granted_sdu.seek(0);
            let granted_msg = Self::build_sapmsg_stealing_ul_dl(granted_sdu, peer_addr, peer_ts, Some(peer_usage), UlDlAssignment::Ul);
            queue.push_back(granted_msg);

            // Reset UMAC inactivity timer — floor granted to peer, expect new TX soon.
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                    call_id,
                    source_issi: peer_addr.ssi,
                    dest_gssi: holder_ssi,
                    ts: peer_ts,
                }),
            });
            return;
        }

        let call_entry = self
            .active_calls
            .iter()
            .find(|(_, call)| call.ts == ts && call.tx_active)
            .map(|(id, _)| *id);

        let Some(call_id) = call_entry else {
            // Check if an echo session owns this timeslot — if so, reset the UL inactivity
            // timer by emitting FloorGranted so UMAC keeps the circuit alive.
            if let Some(ref session) = self.echo_session {
                if session.ts == ts {
                    tracing::debug!("UL inactivity timeout on echo ts={} — refreshing FloorGranted", ts);
                    let call_id = session.call_id;
                    let fake_issi = 0u32;
                    queue.push_back(tetra_saps::SapMsg {
                        sap: tetra_core::Sap::Control,
                        src: tetra_core::tetra_entities::TetraEntity::Cmce,
                        dest: tetra_core::tetra_entities::TetraEntity::Umac,
                        msg: tetra_saps::SapMsgInner::CmceCallControl(
                            tetra_saps::control::call_control::CallControl::FloorGranted {
                                call_id,
                                source_issi: fake_issi,
                                dest_gssi: fake_issi,
                                ts,
                            }
                        ),
                    });
                    return;
                }
            }
            tracing::debug!("UL inactivity timeout on ts={} but no active transmitting call found", ts);
            return;
        };

        let call = self.active_calls.get_mut(&call_id).unwrap();
        tracing::warn!("UL inactivity timeout on ts={}, forcing TX ceased for call_id={}", ts, call_id);

        let dest_gssi = call.dest_gssi;
        let is_network_origin = matches!(call.origin, CallOrigin::Network { .. });
        call.tx_active = false;
        call.hangtime_start = Some(self.dltime);

        self.send_d_tx_ceased_facch(queue, call_id, dest_gssi, ts);

        queue.push_back(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
        });

        // Notify Brew the floor was released. Network-origin calls mirror the inbound admission
        // predicate (FH-FEAT-032 R3) so an admitted foreign/non-whitelisted GSSI still propagates
        // floor events; local-origin calls keep the outbound routing predicate.
        let notify_brew = if is_network_origin {
            net_brew::is_brew_inbound_allowed(&self.config, dest_gssi)
        } else {
            net_brew::is_brew_gssi_routable(&self.config, dest_gssi)
        };
        if notify_brew {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Brew,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
            });
        }
    }
}
