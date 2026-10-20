# Changelog

All notable changes to the `dynamic_cyber_range` tooling are recorded here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); dates are
ISO (YYYY-MM-DD). This file is updated on every repo change.

## [Unreleased] — branch `feature/dynamic-cyber-range`

### 2026-10-20

#### Added
- **Objective catalog + generator** (`c9e9948`). `scenarios/objectives.yaml` lists
  11 OT/ICS crown-jewel objectives grouped by MITRE ATT&CK for ICS tactic
  (A physical impact, B loss of view, C inhibit safety, D persistence, E logic
  theft, F compromise EWS / defeat monitoring, G OT extortion).
  `scenarios/gen_scenarios.py` stamps a matched **static (Red-only)** and
  **dynamic (Red+Blue)** pair per objective into `scenarios/generated/` (22 files).
  Each Red brief states the goal only (no map/IPs).

#### Changed
- **Black-box reconnaissance for Red** (`d258c0d`). The Red/APT prompt and operator
  messages no longer embed the network map or the solution path (ICS subnet,
  OpenPLC, manual-mode coil, repo hints). Red now gets only its entry foothold +
  a macro-objective and must discover the infrastructure — matching the paper
  (§4.1). Blue keeps full white-box knowledge (the intended asymmetry).
- Red safety guardrail reconciled with impact objectives: the plant is fully
  simulated, so a simulated physical effect (even a rupture) is a legitimate
  outcome when it is the assigned objective; scope limits unchanged.

#### Fixed
- **EWS zone** (`5c856fe` → reverted by `5c70d7b`). Net result: scenarios/flag
  manifest keep EWS on the ICS zone (`192.168.95.5`), matching the upstream
  topology this fork tracks. (The transient DMZ placement matched a separate,
  host-specific deployment that this fork does not target.)

#### Docs
- Added this `CHANGELOG.md` and started documenting every repo change.
- Refreshed the README Layout section (now lists `CHANGELOG.md`, `objectives.yaml`,
  `gen_scenarios.py` and `scenarios/generated/`); README asymmetry, objectives and
  flags/metrics sections brought in line with the code.

### 2026-10-19

#### Added
- **Initial dynamic cyber range tooling** (`f57e1e4`). Implements the two paper
  conditions on the live GRFICSv3 range: Scenario 1 (static, Red only) and
  Scenario 2 (dynamic, Red + Blue). Includes the TRACE-loop agent engine and
  Red/Blue prompts, a scope-enforced `docker exec` executor, static/dynamic
  orchestration with transcripts, a stdlib OpenAI-compatible mock model for
  GPU-free smoke tests, and model-agnostic config (Qwen3 via any OpenAI endpoint).
- **Flag scheme + experiment metrics** (`c4dd4ca`). Host flags (token files per
  target container) + a live OT-impact probe (PLC Modbus coil 0). Scoring
  (`dcr/metrics.py`) produces the paper's metrics: flags captured / capture rate,
  hosts compromised, time-to-first-flag, OT impact, attacker success %, and (for
  dynamic) defender success % plus heuristic hardening/detection times. Written to
  `metrics.json` + `summary.md` per run.

## Deployment notes (local, not committed to the fork)

These host-specific changes live only in the working tree (via `.git/info/exclude`),
since they are specific to this machine and to isolating this variant:

- `docker-compose.override.yml`: macvlan parents point at the host's dummy
  interfaces `grfics-ics` / `grfics-dmz` (this host has no `eth0`); sets the Compose
  project name `grfics_article`; re-pins the five data volumes to `grfics_article_*`
  so this variant's data is fully separated from the other GRFICSv3 variants on the
  machine (original, RESILTECH).
