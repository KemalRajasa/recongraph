# Sample datasets

Each folder holds one sample. A sample includes:

- the Plaso timeline in two forms: JSON Lines (`psort -o json_line`) and CSV (`psort -o dynamic`);
- the ReconGraph output for both node modes;
- the original log, when it is small enough to include (the Windows samples).

| Folder | Source | Log | Plaso events | License |
|---|---|---|---|---|
| [`windows_sideload/`](windows_sideload/) | EVTX-ATTACK-SAMPLES | Sysmon, DLL side-loading, UAC bypass, rundll32 injection, C2 | 36 (18 EVTX records) | GPL-3.0 |
| [`windows_psexec/`](windows_psexec/) | EVTX-ATTACK-SAMPLES | Sysmon, PsExec over SMB, Meterpreter | 20 (10 EVTX records) | GPL-3.0 |
| [`linux_cam-lds/`](linux_cam-lds/) | CAM-LDS | auditd, Apache access log, syslog, wtmp of a Linux web server, privilege escalation to root and SSH key persistence | 101,772 (window 76,626) | CC-BY-4.0 |

Each folder has a `README.md` with the source, the license, how its files were made, and its node and edge counts.
The license of a sample applies to every file in its folder; the rest of this repository is MIT licensed.

## Using a sample

Timelines and graphs are compressed with xz. ReconGraph and the visualizer read only uncompressed files, so extract
them first. `-k` keeps the `.xz` files.

```bash
xz -dk dataset/windows_psexec/*.xz dataset/windows_psexec/*/*.xz
```

Then run ReconGraph on the timeline:

```bash
recongraph -f dataset/windows_psexec/psexec.jsonl -r /path/to/hayabusa-rules/sigma \
  --exclude-status deprecated,unsupported --exclude-rules-file /path/to/hayabusa-rules/config/exclude_rules.txt \
  --node drain -o result/psexec-drain
```

Alternatively, open the GraphML files of a sample in the visualizer (`recongraph_agg.graphml`) or import them into
Neo4j (`recongraph_temporal.graphml`).

## Versions

The files were made with these versions:

| | Version |
|---|---|
| Plaso | `log2timeline/plaso` Docker image, version 20261027 |
| ReconGraph | commit `4ace7a0` |
| Rules, Windows samples | [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) commit `58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`, folder `sigma`, flexible matching, `--exclude-status deprecated,unsupported --exclude-rules-file config/exclude_rules.txt` |
| Rules, Linux sample | [SigmaHQ](https://github.com/SigmaHQ/sigma) commit `483b91bb583250faca0aa87415d4187a3ea2c957`, folders `rules/linux` and `rules/web` copied into one folder (256 rules), `--strict` |

Other rule versions give other Sigma labels, so their graphs can differ from the ones stored here. In
`recongraph_meta.json`, `input_file` and `sigma_rules_path` are relative to the folder ReconGraph was run from. That
folder held `dataset/`, `hayabusa-rules` (a clone of hayabusa-rules) and `sigma-linux-web` (the 256 SigmaHQ rules).
