<!--
SPDX-FileCopyrightText: 2026 Chris YO3TCO / Nexus-BS Project
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
SPDX-FileComment: Central change notice for Nexus-BS modifications and additions.
-->

# Nexus-BS Central Change Notice

This file is the central change notice for Nexus-BS modifications and additions.
Per-file SPDX comments may reference this file so that individual files do not
need to repeat the full project-level change summary.

This notice is not legal advice.

## Relationship To Upstream Work

Nexus-BS is derived from the historical BlueStation and FlowStation TETRA
base-station lineages and also carries credits for related upstream TETRA, SDR,
dashboard, deployment, testing, and community work.

This notice does not relicense upstream material. Upstream portions that were
provided under Apache-2.0 remain Apache-2.0, and their upstream license notices
and attribution requirements continue to apply. The Apache-2.0 license text is
preserved in `LICENSES/Apache-2.0.txt`.

## Nexus-BS Changes

Nexus-BS modifications and additions include, without limitation:

- TETRA base-station behavior changes across CMCE, MM, LLC, MLE, UMAC/MAC,
  SDS/status, WAP, dashboard, telemetry, control, Brew interconnect, RF/SDR
  operation, service supervision, packaging, and deployment material;
- field-oriented hardening, operator dashboard work, health checks, restart and
  recovery behavior, configuration handling, and systemd integration;
- tests, examples, documentation, release packaging, and distribution material;
  and
- project identity, branding, notices, and documentation for the Nexus-BS
  project form.

The README describes the engineering delta and project status in more detail.
Those engineering metrics are not a formal conformance certificate.

## License Effect Of Nexus-BS Changes

Unless a file-level notice states otherwise, Nexus-BS modifications and
additions are licensed by Chris YO3TCO / Nexus-BS Project under the PolyForm
Noncommercial License 1.0.0. The license text is available in `LICENSE` and
`LICENSES/PolyForm-Noncommercial-1.0.0.txt`.

Commercial licensing offered by Chris YO3TCO / Nexus-BS Project applies only to
Nexus-BS-covered material and only to the extent permitted by applicable
upstream licenses. A Nexus-BS commercial agreement does not remove, replace, or
narrow rights granted directly by upstream copyright holders under Apache-2.0
or any other upstream license.

## Redistribution Notice

When redistributing source, binaries, bundles, or derivative works that include
Nexus-BS-covered material, preserve this file, `NOTICE`, `LICENSE-OVERVIEW.md`,
the applicable license texts under `LICENSES/`, and all applicable file-level
SPDX, copyright, attribution, and license notices.

## flowstation-miura

This repository (flowstation, `miura` line) is Apache-2.0. It imports a few
files from Nexus-BS, copied or adapted with the permission of Chris YO3TCO.
Those files keep their original SPDX headers and add an `SPDX-FileComment`
line describing the adaptation; everything else in this repository stays
Apache-2.0. The list of imported files is kept in `NOTICE`.

The sections above are copied verbatim from Nexus-BS. In this repository:

- `LICENSE` is the Apache-2.0 text (there is no `LICENSES/Apache-2.0.txt`).
  The PolyForm Noncommercial 1.0.0 text is only in
  `LICENSES/PolyForm-Noncommercial-1.0.0.txt`; the .deb package installs it,
  with `NOTICE`, next to this file in `/usr/share/doc/flowstation/`.
- `LICENSE-OVERVIEW.md` is not included: `NOTICE` and the PolyForm text cover
  its role for the imported files.
- `crates/tetra-entities/src/umac/subcomp/bs_sched/multislot.rs` (flowstation-miura,
  packet-data channels of several slots): the uplink grant opportunity search
  over the slots of the channel and the grant made when the downlink slot that
  carries it is built follow Nexus-BS `bs_sched.rs`
  (`ul_find_grant_opportunity_on_channel_from`, the pending grant built at
  transmission). Adapted: one uplink debt per channel granted in chunks of up to
  four slots, frame 18 counted but never granted, the half-duplex guard of a
  radio without fast switching (nothing sent in the downlink slots it cannot
  hear, no downlink fragmentation across its uplink), a reply slot on advanced
  link segments that ask for an acknowledgement. 2026-09: extended to
  packet-data channels on a carrier without MCCH (ts1 downlink, no ts1 uplink,
  four slots, frame-18 rules, cross-carrier arrival and hand-off).
