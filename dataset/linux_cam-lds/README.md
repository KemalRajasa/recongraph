# linux_cam-lds

Logs of the Linux web server `videoserver`, which runs ZoneMinder, in scenario `scenario_1_sudo_sshkey` of CAM-LDS. An
attacker scans the web server with ffuf and Nikto and gets a shell as `www-data` through ZoneMinder. The attacker then
runs linpeas, becomes root with `sudo`, adds an SSH key for `root`, logs in with it, and reads `/etc/shadow`. The
attack lasts from 08:58 to 09:23 UTC on 2025-09-22, according to the scenario's `attackmate.json`. The timeline
covers auditd, the Apache access log, syslog and wtmp.

## Source and license

M. Landauer, W. Hotwagner, T. Boenke, F. Skopik, M. Wurzenberger, *Cyber Attack Manifestations - Log Data Set
(CAM-LDS)*, Zenodo, 2026, [doi:10.5281/zenodo.18861762](https://doi.org/10.5281/zenodo.18861762), licensed
[CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). **Every file in this folder is distributed under
CC-BY-4.0**; the rest of the ReconGraph repository is MIT licensed.

The original logs are not included. They are in `scenario_1_sudo_sshkey.zip` of the Zenodo record, under
`videoserver/logs`.

## Changes

These files were derived from `videoserver/logs` (date of this version: 2026-11-26):

| File | How |
|---|---|
| `videoserver.jsonl.xz` | `log2timeline.py --parsers text,utmp` on `videoserver/logs`, then `psort.py -o json_line`; Plaso 20261027; compressed with `xz -9` |
| `videoserver.csv.xz` | the same Plaso storage, `psort.py -o dynamic`; compressed with `xz -9` |
| `videoserver_window.jsonl.xz`, `videoserver_window.csv.xz` | the lines of the two files above with a time in [08:58:00, 09:23:00) UTC on 2025-09-22, unchanged; compressed with `xz -9` |
| `recongraph-drain/`, `recongraph-sigma/` | ReconGraph `4ace7a0` on `videoserver.jsonl`, `--strict`, `--node drain` and `--node sigma`, with the Linux rules of [`../README.md`](../README.md#versions); GraphML compressed with `xz -9` |
| `window-recongraph-drain/`, `window-recongraph-sigma/` | the same, on `videoserver_window.jsonl` |

## Reproduce

Run these commands from the folder that holds the extracted `scenario_1_sudo_sshkey/`:

```bash
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 log2timeline.py --unattended --parsers text,utmp \
  --storage-file /data/videoserver.plaso /data/scenario_1_sudo_sshkey/videoserver/logs
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 psort.py -o json_line -w /data/videoserver.jsonl /data/videoserver.plaso
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 psort.py -o dynamic -w /data/videoserver.csv /data/videoserver.plaso

# the attack window: 1758531480000000 is 08:58:00 and 1758532980000000 is 09:23:00 UTC, in microseconds
python3 -c "import json, sys; sys.stdout.writelines(l for l in sys.stdin
    if 1758531480000000 <= json.loads(l)['timestamp'] < 1758532980000000)" < videoserver.jsonl > videoserver_window.jsonl
{ head -1 videoserver.csv; tail -n +2 videoserver.csv |
  awk -F, '$1 >= "2025-09-22T08:58:00" && $1 < "2025-09-22T09:23:00"'; } > videoserver_window.csv

recongraph -f videoserver.jsonl -r sigma-linux-web --strict --node drain -o recongraph-drain
recongraph -f videoserver.jsonl -r sigma-linux-web --strict --node sigma -o recongraph-sigma
recongraph -f videoserver_window.jsonl -r sigma-linux-web --strict --node drain -o window-recongraph-drain
recongraph -f videoserver_window.jsonl -r sigma-linux-web --strict --node sigma -o window-recongraph-sigma
```

The first line of the CSV is its header, and each later line is one event, so the `awk` filter keeps whole events.

## Graphs

| Folder | Node mode | Rows read | Rows in graph | Nodes | Aggregate edges | Temporal edges |
|---|---|---|---|---|---|---|
| `recongraph-drain/` | drain | 43,775 | 43,775 | 596 | 2,622 | 43,774 |
| `recongraph-sigma/` | sigma | 43,775 | 33,332 | 27 | 97 | 33,331 |
| `window-recongraph-drain/` | drain | 34,914 | 34,914 | 129 | 381 | 34,913 |
| `window-recongraph-sigma/` | sigma | 34,914 | 32,851 | 17 | 40 | 32,850 |

*Rows read* are the rows of the timeline after loading: one per EVTX record (its creation time) and one per audit event. *Rows in graph* are all rows with `--node drain` and the rows with a Sigma label with `--node sigma`.
