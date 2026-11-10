# ReconGraph

**Reconstruction of Forensic Timelines Using Graph Theory**

`recongraph` is a Python library and CLI that reconstructs and visualizes system
behavior from logs of various devices (e.g. Windows and Linux). It converts Plaso
`log2timeline` output into a forensic graph timeline: by parsing sequential log
data, giving every row an event identity and annotating it with **Sigma rules**,
`recongraph` builds a `MultiDiGraph` (Multi-Directed Graph) representing the state
transitions and operational flow of the target system. `recongraph` maps events and
does not judge them: the investigator explores the map and decides which events are of
interest.

This tool is based on the paper:
[Forensic Event Reconstruction for Drones](https://ieeexplore.ieee.org/document/9702864).

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Set Up a Virtual Environment](#set-up-a-virtual-environment)
  - [Install from PyPI](#install-from-pypi)
  - [Install from Source](#install-from-source)
  - [Install via Docker](#install-via-docker)
- [Sigma Rules Setup](#sigma-rules-setup)
- [Quick Start](#quick-start)
  - [Run Locally](#run-locally)
  - [Run with Docker](#run-with-docker)
- [Command-Line Options](#command-line-options)
- [Input Data Format](#input-data-format)
- [Output](#output)
- [Visualizing the Graph](#visualizing-the-graph)
- [Examples](#examples)
- [How to Test](#how-to-test)
- [Documentation](#documentation)
- [Licenses](#licenses)

## Features

- **Every Event on the Map**: By default every timeline row becomes part of the graph, under an event identity: `Provider:EventID` for EVTX, `data_type:timestamp_desc` for structured artefacts, a [Drain3](https://github.com/logpai/Drain3) template for free text. See [Node Modes](#node-modes).
- **Sigma Annotation**: Standard Sigma rules annotate each row; the result is stored on rows and nodes, as a starting point for queries.
- **Forensic Graph Construction**: Transforms sequential log entries from Plaso (log2timeline) into a directed graph, where nodes represent kinds of events and edges represent temporal transitions.
- **Intelligent Log Detection**: Automatically identifies various log formats (e.g., Apache, Linux auth, Syslog) and extracts relevant metadata like HTTP methods, URIs, and status codes.
- **Weighted Behavioral Mapping**: Edges are weighted by transition frequency, helping to distinguish common flows from rare or suspicious sequences.
- **Anomaly-Focused Reconstruction**: Specifically isolates and maps behaviors based on rule severity levels (Critical, High, Medium, Low).
- **Multi-Format Export**: Exports graphs to GraphML for visualization (Gephi, Cytoscape, or the bundled web visualizer) and detailed forensic timelines to CSV.

## Prerequisites

- **Python 3.13 or higher**
- **Git**
- **pip** (and, recommended, a virtual environment via `venv` or `conda`)
- **Sigma rules** — see [Sigma Rules Setup](#sigma-rules-setup)

> Prefer a zero-setup, dependency-free environment? Skip straight to
> [Install via Docker](#install-via-docker) — no local Python required.

## Installation

There are three ways to install `recongraph`: from **PyPI**, from **source**, or
via **Docker**. For the PyPI and source methods, set up a virtual environment
first.

### Set Up a Virtual Environment

Using `venv` (recommended):

```bash
python -m venv venv

# Activate it:
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows (PowerShell / CMD)
```

Or using Anaconda / Miniconda:

```bash
conda create -n recongraph python=3.13
conda activate recongraph
```

### Install from PyPI

```bash
pip install recongraph
```

### Install from Source

1. **Clone the repository**

   ```bash
   git clone https://github.com/forensic-timeline/recongraph
   ```

2. **Install the package (editable mode)**

   ```bash
   cd recongraph
   pip install -e .
   ```

### Install via Docker

This is the **recommended approach** for a fully isolated, dependency-free
environment — no Python installation required on your machine.

> **Prerequisite**: [Docker](https://docs.docker.com/get-docker/) must be installed and running.

The image uses a **multi-stage build** to keep the final image small:

1. A **builder** stage installs build tools and compiles the Python dependencies.
2. A **runtime** stage copies only the compiled libraries and source code, and
   automatically downloads the **Sigma Core** rules into `/app/sigma`.

**Step 1 — Build the image** (run once, from the project root):

```bash
docker build -t recongraph .
```

**Step 2 — Prepare a data directory** for your input logs and output files:

```bash
mkdir data
```

Place your Plaso CSV file (e.g., `forensic_timeline.csv`) inside `data/`.

You are now ready to run the container — see [Run with Docker](#run-with-docker).

## Sigma Rules Setup

`recongraph` uses Sigma rules to label and detect events. **You must provide a
rules directory** — without one, no events are matched and the resulting graph is
empty. The rules directory is resolved in this order:

1. the `-r/--rules` command-line option, if given; otherwise
2. the `SIGMA_RULES_PATH` environment variable, if set.

Download the official rules from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma):

```bash
git clone https://github.com/SigmaHQ/sigma
```

You can then point `-r` at the cloned `sigma/rules` directory (or any folder of
`.yml` rules).

> **Docker note**: the Docker image already bundles the Sigma Core rules at
> `/app/sigma` and sets `SIGMA_RULES_PATH=/app/sigma`, so they are used
> automatically — no `-r` needed. Pass `-r` only to override with your own rules.

Sigma rules are released under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).

## Quick Start

### Run Locally

```bash
recongraph -f /path/to/plaso-file.csv \
           -r /path/to/sigma/rules \
           -o result
```

This writes `recongraph_agg.graphml`, `recongraph_temporal.graphml` and
`recongraph_meta.json` to the folder `result`. Add `--export-events` and
`--export-sigma` to also produce the detailed event-log CSV and the Sigma-labeled CSV:

```bash
recongraph -f forensic_timeline.csv \
           -r ./sigma/rules \
           -o result \
           --export-events \
           --export-sigma
```

### Run with Docker

Mount your local `data/` folder into the container and pass your arguments. The
bundled Sigma Core rules are used automatically (via `SIGMA_RULES_PATH`), so no
`-r` is required:

```bash
# Linux / macOS
docker run --rm -v "$(pwd)/data:/app/data" recongraph \
  -f forensic_timeline.csv \
  -o result \
  --export-events \
  --export-sigma

# Windows (PowerShell)
docker run --rm -v "${PWD}\data:/app/data" recongraph `
  -f forensic_timeline.csv `
  -o result
```

To use **your own** rules instead, mount them as an extra volume and point `-r`
at the mount:

```bash
docker run --rm \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/my_sigma_rules:/app/custom_sigma" \
  recongraph -f forensic_timeline.csv -r /app/custom_sigma
```

Alternatively, use **Docker Compose** (mounts `./data` automatically):

```bash
docker compose run --rm recongraph -f forensic_timeline.csv -o result
```

> `--rm` removes the container after it finishes. All output files are written
> back to your local `data/` folder.

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f`, `--file` | Path to the input file (Plaso CSV, Plaso JSON Lines, or TXT). **Required.** | — |
| `-r`, `--rules` | Path to the Sigma rules directory. | `$SIGMA_RULES_PATH` if set, else none |
| `-o`, `--output-dir` | Folder of this run, created if missing. See [Output](#output). | `recongraph_output/<input>_<node mode>` |
| `--export-events` | Also write `recongraph_events.csv`, the log rows of every graph node. | off |
| `--export-sigma` | Also write `recongraph_sigma.csv`, the input with its Sigma annotation. | off |
| `--overwrite` | Replace the output of an earlier run in the folder. Without it the run stops before writing. Other files are kept. | off |
| `--strict` | Strict logsource validation (category, product and service must match). Without it (flexible mode) only `product` is checked, and only keyword selections fall back to the whole message. | flexible mode |
| `--keep-all-timestamps` | JSON Lines input: keep every timestamp row of an EVTX record (by default only `Creation Time` is kept). | off |
| `--edge-order {time,file}` | Order transitions by timestamp (ties keep row order) or by input row order (the original behavior). | `time` |
| `--node {drain,sigma}` | Node identity, see [Node Modes](#node-modes). | `drain` |
| `--exclude-status` | Do not load rules with these statuses, comma separated (ex: `deprecated,unsupported`). | none |
| `--exclude-rules-file` | Do not load rules whose `id` is listed in this file (format of Hayabusa `exclude_rules.txt`: one UUID per line, `#` starts a comment). | none |

## Node Modes

> **Changed default:** `recongraph` used to map only rows with a Sigma label. The default is now
> `--node=drain`, which maps every row. `--node=sigma` reproduces the old behavior: its GraphML files are
> byte-identical to those of the previous version.

| | `--node=drain` (default) | `--node=sigma` |
|---|---|---|
| Rows in the graph | all | only rows with a Sigma label |
| Node identity | event identity below | primary Sigma label |
| Sigma | annotation on rows and nodes | decides the node |
| Sources without Sigma rules (Android, iOS, ...) | full graph, no marks | empty graph |

Event identity in `--node=drain`:

| Row | Identity (`event_key`) | Example |
|---|---|---|
| EVTX | `Provider:EventID` | `Microsoft-Windows-Sysmon:1` |
| Structured artefact | `data_type:timestamp_desc` (`data_type` alone for a row without `timestamp_desc`). The key depends only on the row, not on the rest of the file | `fs:stat:Last Access Time`, `syslog:ssh:login:Content Modification Time` |
| Free text: `syslog:line`, `systemd:journal`, `android:logcat`, `ios:lockdownd_log:entry`, `ios:sysdiag_log:entry`, `ios:sysdiagnose:logd:line` | `data_type:template` | `syslog:line:Server listening on <IP> port <NUM>.` |

- Drain3 is never used for EVTX, because `EventID` already names the kind of event. It runs with one template
  miner per data type, on the raw line (`message_body`, `body`) rather than the sentence Plaso's formatter builds,
  with GUIDs, SIDs, hex values, IPs, paths and numbers masked, in two stages: all rows train the miner, then each row is
  matched against the final templates.
- EVTX with unparsable XML takes the provider and event ID from Plaso's `message`.
- Plaso CSV has no `data_type` or XML fields. EVTX rows use `Source Name:EventID` from `message`; other rows use `parser`
  in place of `data_type` (`usnjrnl:Metadata Modification Time`); `text/*` parsers use Drain3 on `message`. CSV also holds two rows per EVTX record (creation
  and written time), and all rows are mapped.
- Plain text input is free text with the source `text`.

Sigma never removes a row in `--node=drain`. Find annotated events with a query, for example
`MATCH (n) WHERE n.sigma_hits > 0 RETURN n`, or [`docs/cypher/window_around_sigma.cypher`](docs/cypher/window_around_sigma.cypher)
for the transitions around annotated rows. An annotation is not a verdict: a node with no hit may still be an event of
interest, and sources without rules carry no marks at all.

## Input Data Format

### Log File (`<filename>.csv`)

A sequential log file of system activities. `recongraph` supports the CSV format
produced by Plaso (`log2timeline`).

### Plaso JSON Lines (`<filename>.jsonl`)

For Windows event logs, prefer `psort -o json_line` output. Its `xml_string`
carries the full EVTX event, so `recongraph` can match field-based Sigma rules
(`Image`, `CommandLine`, `TargetImage`, ...), which the CSV `message` column does
not name. A file is treated as JSON Lines when it ends in `.jsonl`/`.json` or its
first line is a JSON object with a `data_type` key.

For each EVTX record `recongraph` extracts `EventID`, `Channel`, `Provider_Name`,
`Computer`, `EventRecordID`, `Security_UserID` and every `EventData`/`UserData`
field, derives the Sigma logsource (service from `Channel`, category from Sysmon,
PowerShell and Security 4688 event IDs), keeps one row per record (`Creation Time`),
drops timestamps before 1970 and sorts by time. The input file is never modified.

- `Channel` holds the `UserData` channel when present (e.g. the cleared log of
  EventID 104); the logsource is always derived from the `System` channel.
- `Data` elements without a `Name` become `param1`, `param2`, ... and are also
  joined with newlines into a `Data` field.
- Control characters that are illegal in XML 1.0 are removed before parsing; events
  whose XML is still unparsable keep only the generic columns.

```bash
psort.py -o json_line -w timeline.jsonl timeline.plaso
recongraph -f timeline.jsonl -r ./sigma/rules/windows --strict
```

### Sigma Rules (rules directory)

A directory of standardized Sigma rules in `.yml` format that define the detection
logic used to label events. See [Sigma Rules Setup](#sigma-rules-setup).

## Output

Each run writes to one folder, with fixed file names. In both node modes the two graphs and the metadata are always
written, also when the graphs are empty (`--node=sigma` without a detection):

- **Aggregate GraphML** (`recongraph_agg.graphml`): A directed graph where
  nodes are kinds of events and edges represent the flow between them. Suitable
  for the bundled visualizer, Gephi, or Cytoscape. Each edge carries `label`
  (always `NEXT`, the relationship type when imported into Neo4j), `weight`
  (number of transitions), `first_seen`/`last_seen` (ISO 8601 UTC, plus `_us`
  epoch microseconds) and `delta_min_us`/`delta_median_us`/`delta_max_us`; nodes
  carry `first_seen`/`last_seen` too, and `tactics` and `techniques`: the ATT&CK tags of every Sigma rule that
  matched one of the node's rows, unique and separated by ` | `, tactics by their official name in matrix order.
  They describe what the rules can detect, not the stage of an attack.
  Time attributes are omitted when timestamps
  are missing or invalid. With `--node=drain` nodes also carry `event_key`, `row_count`,
  `sigma_hits` (rows with a Sigma annotation), `sigma_rules` (unique, sorted, separated
  by ` | `) and `sigma_max_level`, and have no `level`; with `--node=sigma` they carry `level`.
- **Temporal GraphML** (`recongraph_temporal.graphml`): the same nodes with one
  edge per consecutive transition: `label` (as above), `seq`, `t_src`/`t_dst` (+ `_us`), `delta_us`,
  and `src_row`/`dst_row` (row index in the Sigma-labeled data). With `--node=drain`
  also `src_level`/`dst_level`: the Sigma level of the two rows, empty when not annotated.
- **Event Logs CSV** (`recongraph_events.csv`, only with `--export-events`): A
  detailed breakdown of every log entry associated with a graph node, including
  timestamps and raw message content, plus `row_index` and `timestamp_us` to trace
  temporal edges back to their log rows and `event_key`, the identity of the row's node, so
  the content of any node can be opened. With `--node=drain` also the row's `sigma`,
  `sigma_all` and `level`.
- **Sigma Labeled CSV** (`recongraph_sigma.csv`, only with `--export-sigma`):
  The input log file augmented with matching Sigma rule titles and severity levels:
  `sigma` holds the primary label (highest severity, ties broken alphabetically by label) and
  `sigma_all` every matching rule, sorted and separated by ` | `; `sigma_ids` the `id` of every matching rule, sorted
  by ID and separated by ` | ` (not aligned with `sigma_all`, where rules with the same title and level are one label);
  `sigma_tactics` and `sigma_techniques` the union of the ATT&CK tags of those rules (`sigma_techniques` also holds group and software IDs).
  Rules that use a field modifier
  ReconGraph does not implement are skipped with a warning when the rules are loaded.
  With `--node=drain` also `event_key` and `sigma_level`.
- **Run Metadata** (`recongraph_meta.json`): the configuration of the run, in a separate file
  so that GraphML stays plain and `--node=sigma` output differs from earlier versions only by the edge `label` and the node `tactics` and `techniques`: `node_mode`, `edge_order`,
  `input_file`, `sigma_rules_path`, `sigma_matching`, `sigma_rules` (rules loaded, skipped per reason, and the exclude options), `keep_all_timestamps`, `recongraph_version`, `rows_total`,
  `rows_in_graph`, under `event_sources` how each source was treated and its row count (`evtx`, `structured`, `free_text`;
  the source is the `data_type`, or `parser` for Plaso CSV; empty with `--node=sigma`), and under `drain3` the version, the
  configuration (`sim_th`, `depth`, `max_children`, masking) and a snapshot of each template miner. The same input and
  configuration give the same GraphML.

## Reconstructing Paths Between Events

`python -m recongraph.reconstruct` lists the paths between two events of a graph
(the aggregate graph is optional):

```bash
recongraph -f timeline.jsonl -r ./sigma/rules/windows --strict -o result
python -m recongraph.reconstruct --temporal result/recongraph_temporal.graphml --agg result/recongraph_agg.graphml \
       --src "Base64 Encoded PowerShell" --dst "Malware Callback" --mode compare --max-len 8 --max-gap 60s
```

| Mode | Paths |
|------|-------|
| `dfs` | Simple paths in the aggregate graph (no repeated node, time ignored): the classic baseline. |
| `time` | Time-respecting walks: each transition starts no earlier than the previous one ended (and at most `--max-gap` later); events may repeat, a transition is used once. |
| `replay` | Consecutive transitions as they appear in the log (`seq`, `seq + 1`, ...). |
| `compare` | All three, plus how many DFS paths are temporally impossible (no time-respecting walk visits the same events). |

`--src`/`--dst` take a node id, an exact label or a unique label substring; `--cap`
limits the number of paths per method (`truncated` is reported), `--out` writes JSON.
Equivalent Neo4j queries are in [`docs/cypher/`](docs/cypher/).

## Visualizing the Graph

The repository ships with a standalone, single-file web visualizer at
[`recongraph/visualizer.html`](recongraph/visualizer.html). It requires no build
step or server:

1. Open `recongraph/visualizer.html` in a web browser.
2. Click **Load GraphML** (or drag the file onto the page) and select your
   `recongraph_agg.graphml`.

The visualizer provides force-directed, circular, hierarchical, and radial
layouts, severity filtering, node search, a node inspector, and SVG/JSON export.

## Examples

The [`dataset/`](dataset/) folder contains ready-made sample datasets, each with
its source Plaso CSV, the resulting GraphML, and the SVG/JSON exported from the
visualizer:

| # | Scenario / behavior | Folder |
|---|---------------------|--------|
| 1 | Credential access — failed logins | [`dataset/1/`](dataset/1/) |
| 2 | Defense evasion — Windows Firewall disabled (EVTX) | [`dataset/2/`](dataset/2/) |
| 3 | Anti-forensics — system time change (Event ID 4616) | [`dataset/3/`](dataset/3/) |

For a full step-by-step walkthrough on reproducing these samples (generating the
GraphML, exporting SVG/JSON, and a flexible-vs-strict comparison), see the
[Examples & Sample Datasets](https://recongraph.readthedocs.io/en/latest/examples.html)
page in the documentation.

## How to Test

The test suite lives in the `tests/` directory.

1. **Install the test dependencies**:

   ```bash
   pip install pytest pandas pyyaml
   ```

2. **Run the tests** from the project root:

   ```bash
   pytest -v
   ```

   You should see output indicating that all tests pass.

## Documentation

Full documentation is available at
[ReadTheDocs](https://recongraph.readthedocs.io/), including a step-by-step
[Examples & Sample Datasets](https://recongraph.readthedocs.io/en/latest/examples.html)
walkthrough.

## Licenses

### ReconGraph

This project is licensed under the [MIT License](LICENSE).

### Third-Party Licenses

This project uses **Sigma Rules** for event detection:

- The **Sigma specification** and logo are public domain.
- The **detection rules** from the [SigmaHQ repository](https://github.com/SigmaHQ/sigma)
  are released under the
  [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
