# Munshi

**Evidence-linked SSH authentication log analysis.**

Munshi analyzes OpenSSH authentication logs, detects suspicious authentication patterns, and produces structured incident narratives that can be traced back to parsed log events.

It combines rule-based detection, a Flask API, an interactive web interface, synthetic attack datasets, and tests for evidence verification.

## Features

- **SSH log parsing:** Parses supported authentication events and reports lines that could not be understood.
- **Brute-force detection:** Identifies repeated failed authentication attempts.
- **Password-spray detection:** Identifies suspicious patterns involving multiple usernames.
- **Threshold-dodging detection:** Correlates repeated bursts that may remain below ordinary per-episode thresholds.
- **Low-and-slow detection:** Correlates appropriately spaced failures over longer periods.
- **Distributed-campaign detection:** Correlates suspicious authentication failures across multiple source IP addresses.
- **Authentication context:** Preserves relevant successful-login observations without automatically treating them as proof of compromise.
- **Evidence-linked narratives:** Generates deterministic claims and checks their structured values, wording, and supporting log-line references.
- **Evaluation tools:** Compares findings against synthetic ground-truth data and supports multi-seed evaluation.
- **Interactive interface:** Provides a premium web interface for analyzing findings, inspecting evidence, and reviewing evaluation results.

An IP address identifies a network endpoint, not necessarily a person. A detected pattern is a security signal, not proof of malicious intent.

## Requirements

- Python and pip
- A modern web browser
- Node.js is optional and is only needed for the JavaScript syntax checks described below.

The project declares Flask as its Python dependency in `requirements.txt`.

## Installation

Run these commands from the project directory in PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, use an appropriate activation method for your shell or invoke the environment's Python executable directly.

## Generate the sample datasets

Munshi provides synthetic easy and hard datasets with corresponding ground-truth information.

Generate both datasets:

```powershell
python generate_logs.py
python generate_logs.py --hard
```

The application expects these generated files under `logs/`:

- `auth.log`
- `ground_truth.json`
- `auth_hard.log`
- `ground_truth_hard.json`
- `benign_hard.json`

These datasets are intended for development and repeatable testing, not as substitutes for representative production logs.

## Run Munshi

Start the Flask application from the project root:

```powershell
python app.py
```

Open the local application in your browser:

**http://127.0.0.1:5000**

The homepage redirects to the premium interface in `static/munshi-vnext/`. The application is configured to listen on the local loopback address and runs with Flask debug mode disabled.

You can upload a supported SSH authentication log through the interface or analyze one of the built-in synthetic samples.

The upload limit is 2 MiB. Unsupported or malformed lines may be reported as skipped rather than interpreted as authentication events.

## Put the demo on your phone

For a phone-only demo, deploy Munshi as a web service instead of relying on
`127.0.0.1` on your laptop. The repository includes a Render deployment
configuration in [`render.yaml`](./render.yaml).

1. Push this repository to GitHub.
2. Create a Render account and choose **New > Blueprint**.
3. Select the GitHub repository and confirm the `render.yaml` configuration.
4. Wait for the deployment to finish, then open the HTTPS URL from your phone.

The deployment build generates the built-in easy and hard sample datasets, and
the service uses Gunicorn with the port supplied by Render. Uploaded logs are
processed in memory and are not saved by the app.

## Detection approach

Munshi combines multiple rule-based strategies:

| Detection strategy | Purpose |
|---|---|
| Brute force | Detects repeated failures associated with a source IP and authentication episode. |
| Password spray | Detects failures targeting multiple usernames in a suspicious pattern. |
| Threshold dodging | Correlates recurring bursts that could evade a single-burst threshold. |
| Low and slow | Correlates failures spread over a longer time period. |
| Distributed campaign | Correlates suspicious failures across multiple source IPs. |

Detection thresholds and correlation settings are defined in `munshi/detectors.py`.

The rules are deterministic for a given dataset and configuration. They can still produce false alarms or miss activity that does not fit their assumptions.

### Distributed findings

A distributed finding represents a correlated campaign and can contain multiple participating source IPs. Its representative `ip` field is retained for compatibility, while `source_ips` identifies the participating addresses.

Distributed detection does not, by itself, establish that any account was successfully compromised. Successful-login attribution must be supported and assessed separately.

## Evidence-linked narratives

The narrative implementation is in `munshi/narrative.py`.

It derives structured facts from findings and parsed events, drafts claims from those facts, and verifies claims against the source data. Claims that cannot pass verification are not presented as verified claims.

Evidence references identify source log-line numbers. The API also exposes the associated evidence text for the interface.

The narrative system is a deterministic verification mechanism for its supported claim types. It is not a general-purpose natural-language proof system, and verified wording does not establish attacker identity or intent.

## API

The Flask application exposes these endpoints.

### Analyze a built-in sample

**POST `/api/analyze`**

Send JSON containing the sample name:

```json
{
  "sample": "hard"
}
```

Use `"easy"` to analyze the easy sample.

### Analyze an uploaded log

**POST `/api/analyze`**

Send a multipart form upload using the field name `logfile`.

The response contains a summary and serialized findings, including relevant fields such as:

- Finding type and representative source IP
- Participating source IPs
- Failure counts and targeted usernames
- Successful-authentication context
- Evidence previews
- Narrative claims and verification status
- Source lines referenced by verified narrative claims

### Evaluate a built-in sample

**GET `/api/score?set=easy`**

**GET `/api/score?set=hard`**

These endpoints compare detected findings with the corresponding synthetic ground-truth dataset.

They require the sample files and answer keys to have been generated.

## Tests

Run the complete Python test suite from the project root:

```powershell
python -m unittest -v
```

The test suite covers parsing, detection rules, advanced detection strategies, synthetic ground truth, narrative verification, and Flask API behavior.

To check the syntax of the JavaScript files when Node.js is installed:

```powershell
node --check .\static\app.js
node --check .\static\munshi-vnext\app.js
```

Python syntax can be checked with:

```powershell
python -m py_compile app.py munshi/narrative.py tests/test_app.py tests/test_narrative.py
```

## Evaluation and limitations

Munshi includes synthetic ground-truth datasets and evaluation tooling, including multi-seed evaluation through `munshi/evaluate_seeds.py`.

Evaluation results describe performance against the specific generated datasets and their ground-truth labels. They should not be interpreted as estimates of production precision, recall, or detection accuracy.

Important limitations:

- Detection is rule-based and depends on configured thresholds and correlation assumptions.
- Shared or reused IP addresses can contribute to false alarms.
- Forgotten-password retry clusters remain an open false-alarm source. Munshi does not currently suppress them with same-log login history because a prior successful authentication from an address must not make later suspicious failures from that address invisible.
- Unusual timing, log formats, or attack strategies may evade the rules.
- A successful authentication near a cluster of failures does not automatically prove that the same actor caused both.
- Distributed correlation does not establish compromise or attribute an attack to a particular person.
- The current application analyzes supplied logs or built-in samples; it is not a live monitoring agent.

Evaluate the system on representative, authorized datasets before relying on it for operational security decisions.

## Project structure

```text
munshi/
├── app.py
├── generate_logs.py
├── requirements.txt
├── README.md
├── munshi/
│   ├── detectors.py
│   ├── evaluate.py
│   ├── evaluate_seeds.py
│   ├── narrative.py
│   └── parsing.py
├── static/
│   ├── app.js
│   └── munshi-vnext/
│       ├── index.html
│       ├── app.js
│       └── styles.css
├── tests/
│   ├── test_advanced_detection.py
│   ├── test_app.py
│   ├── test_detectors.py
│   ├── test_hard.py
│   ├── test_narrative.py
│   └── test_parsing.py
└── logs/  # Generated synthetic datasets; excluded from Git
```

## Security and responsible use

Use Munshi only with logs you are authorized to analyze. Keep real authentication logs protected because they may contain usernames, network addresses, hostnames, and sensitive operational information.

Munshi is a development and analysis project, not a replacement for a production security monitoring platform or a complete incident-response process.
