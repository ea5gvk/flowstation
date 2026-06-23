# FACCH / D-CONNECT Fix Report

## Problem

Private duplex call setup was reaching:

- `U-SETUP`
- `DCallProceeding`
- `DSetup`
- `U-ALERT`
- `DAlert`
- `U-CONNECT`

but the caller side still behaved like it got "no answer" or did not properly accept the connect phase.

The recurring runtime symptom was:

- caller-side connect/release signalling on the traffic channel or MCCH would retransmit
- one connect-phase downlink delivery to the caller would exhaust LLC retransmissions
- release sometimes looked correct, but the connect phase was still broken

## What Was Checked

The current tree was compared directly against:

- `tetra-bluestation-feature-duplex-calls-brew`

The analysis followed the full path:

1. CMCE `DConnect` / `DConnectAcknowledge` generation
2. MLE forwarding
3. LLC BL-DATA / BL-UDATA / BL-ACK piggyback handling
4. UMAC MCCH scheduling
5. UMAC FACCH/STCH `MAC-RESOURCE` construction

## Confirmed Divergences Found

### 1. MCCH random-access flag handling differed from reference

Current code was treating all SSI-addressed MCCH downlink signalling as random-access responses.

Reference behavior is:

```rust
let is_random_access_response =
    prim.main_address.ssi_type != SsiType::Gssi && prim.link_id != 0;
```

This was restored.

Effect:

- prevents unsolicited SSI MCCH signalling from being marked as random-access
- aligns MCCH signaling acceptance behavior with the reference

### 2. LLC link context was preserved where the reference clears it

Current code preserved `link_id` through:

- BL-ACK piggyback payload indications
- BL-DATA indications
- BL-UDATA indications
- stealing-path BL-UDATA fallback

The reference clears those back to `0` on the relevant paths.

This was restored.

Effect:

- prevents non-reference "linked" control-context leakage back into MLE/CMCE
- makes control signaling flow match the reference behavior more closely

### 3. FACCH/STCH `MAC-RESOURCE` header had drifted from the reference

This turned out to be the most important fix.

Current FACCH/STCH short-path behavior had two problems:

- it still encoded a `usage_marker` in stolen `MAC-RESOURCE`
- it no longer wrote fill bits after serializing `MAC-RESOURCE + LLC PDU`

Reference behavior:

- `usage_marker: None` on FACCH/STCH `MAC-RESOURCE`
- fill bits are written after header + SDU packing

This was restored.

Effect:

- the stolen `DConnect` / `DRelease` block is now encoded like the reference
- the short STCH block is no longer malformed due to missing fill bits

## Most Likely Root Cause

The final, most likely real root cause of the "no answer" behavior was the malformed FACCH/STCH connect-phase block.

Specifically:

- the short stolen-block path in UMAC was not writing fill bits

That can cause the radio to reject or misparse the stolen `DConnect` block even when CMCE, MLE, and LLC logic are otherwise correct.

## Files Changed

### Final relevant fixes

- `crates/tetra-entities/src/umac/umac_bs.rs`
- `crates/tetra-entities/src/llc/llc_bs_ms.rs`

### Supporting / regression tests

- `crates/tetra-entities/tests/test_umac_bs.rs`
- `crates/tetra-entities/tests/test_llc_bs.rs`

### Earlier CMCE integration restore after reference merge

- `crates/tetra-entities/src/cmce/cmce_bs.rs`
- `crates/tetra-entities/src/cmce/subentities/sds_bs.rs`
- `crates/tetra-entities/src/cmce/subentities/mod.rs`

Those earlier CMCE/SDS restores were required to keep the current repo features and fix the compile error after the CMCE reference transplant, but they were not the final connect-path root cause.

## Exact Behavioral Fixes Applied

### UMAC

- MCCH `random_access_flag` now requires `link_id != 0`
- FACCH/STCH now uses `usage_marker: None`
- FACCH/STCH short path now writes fill bits after packing the block
- FACCH/STCH random-access flag only propagates from an actual pending RA ACK
- traffic-slot `MAC-ACCESS` no longer contaminates later FACCH as random-access

### LLC

- BL-ACK piggyback payload indication now matches reference link handling
- BL-DATA / BL-UDATA indications now match reference link handling
- stealing BL-UDATA fallback now uses unlinked LLC context like the reference

## Verification Performed

Verified in the deploy tree:

- `/home/mihajlo/src/flowstation`

Commands run:

```text
cargo test -p tetra-entities --test test_llc_bs -- --nocapture
cargo test -p tetra-entities --test test_umac_bs test_facch_stealing_does_not_set_random_access_flag_without_pending_ra -- --nocapture
cargo test -p tetra-entities --test test_umac_bs test_traffic_mac_access_does_not_mark_next_facch_as_random_access -- --nocapture
cargo build -p bluestation-bs --bin bluestation-bs --target aarch64-unknown-linux-gnu --release
```

All passed.

## Conclusion

The issue was not just "CMCE logic". The decisive failure was lower-layer signaling encoding drift from the working reference.

The most important final fix was:

- restoring correct FACCH/STCH `MAC-RESOURCE` encoding, especially writing fill bits on the short stolen-block path

If the latest runtime test is now working, that is the fix that most likely resolved it.
