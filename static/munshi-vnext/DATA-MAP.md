# Data map (verified against app.py, detectors.py, evaluate.py)

| UI element | Source |
|---|---|
| Events analyzed / skipped / findings | `summary.events`, `summary.skipped`, `summary.findings` from `POST /api/analyze` |
| With authentication observed | count of findings where `episode_success_count > 0` or `compromised` (computed client-side) |
| False alarms (Watch) | `false_alarms` from `GET /api/score?set=` (samples only) |
| Donut | count of `findings[].label`, colors by type |
| Recent findings | `findings[]` sorted by `start` descending (top 6) |
| Findings search/sort | client-side over `ip, users, label, start, failures` |
| Command palette | navigation items + loaded `findings[]` |
| Evidence timeline | `evidence_preview[].line` and the time prefix of `.text`; success lines from `episode_success_lines` |
| Report evidence refs | first/last of `evidence_preview[].line`, `evidence_total` |
| Hero panel | illustrative only, not API data |
| Bar chart | `findings[].failures`, ordered by `start`; no invented time series |
| Findings by type | count of `findings[].label` |
| Queue row | `label, ip, start, failures, n_users, episode_success_*` |
| Details | `ip, start, end, users (max 10), n_users, evidence_total` |
| Raw log | `evidence_preview[]` `{line, text}` (max 25 per finding); lines in `episode_success_lines` highlighted |
| Chronicle | findings sorted by `start`; only returned values, no narrative |
| Evaluation | `planted, detected, correct_type, false_alarms, false_alarm_causes, by_variant{planted,detected,correct_type}`; "Missed" = planted − detected (computed) |
| Reports | JSON/CSV built in the browser from the same responses; print via `window.print()` |

## Request formats
- Upload: `multipart/form-data`, field `logfile`, max 2 MB (413 otherwise).
- Sample: JSON `{"sample":"easy"|"hard"}`.
- Score: `GET /api/score?set=easy|hard`.

## Not available from the backend
- Per-attack results (which planted attack was missed): the API returns counts only.
- Per-event timestamps beyond the finding's `start`/`end` and the raw text; no timeline chart of individual events.
- Evidence beyond 25 lines per finding; usernames beyond 10.
- Narratives, severity scores, PDF generation, live monitoring: not implemented.
- Year: logs have none; the parser assumes 2026.

## Live effects (decorative; none of this is data)
- Terrain layers and evolving wave contours, light trail on the route, pointer spotlight, parallax: decoration only. Decorative contour dots and floating particle effects are omitted. They do not represent real events or telemetry.
- Landing hero panel: illustrative sample, labelled as such.
- Workspace effects tied to real state: charts/rates animate once when an API response arrives; the dataset pill dot reflects busy / loaded / error from the actual request; the path graphic uses `failures, kind, evidence_total, episode_success_*`; the evidence node lights when a raw line is selected.
