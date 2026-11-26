# windows_psexec

A machine at 10.0.2.19 connects to the Windows host IEWIN7 (10.0.2.18) over SMB and creates a service that runs hidden, encoded PowerShell as SYSTEM, which connects back to 10.0.2.19 on port 4444. Sysmon, 10 records, about 1.6 seconds on 2019-04-30.

## Source and license

`psexec.evtx` is `Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx` from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by
sbousseaden (uploaded 2019-05-14, repository commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`), unchanged:

```
SHA-256 18ffdda9c24e593d6b1414b6e05c7f7a5dbffb8588a387c165431b61ab52d76f
```

EVTX-ATTACK-SAMPLES is licensed under the GNU General Public License v3.0, included as [`LICENSE.GPL`](LICENSE.GPL).
**Every file in this folder is distributed under GPL-3.0**, the files derived from `psexec.evtx` included; the rest
of the ReconGraph repository is MIT licensed.

## Modified

The other files of this folder were derived from `psexec.evtx` (date of this version: 2026-11-26):

| File | How |
|---|---|
| `psexec.jsonl.xz` | `log2timeline.py --parsers winevtx`, then `psort.py -o json_line`; Plaso 20261027; compressed with `xz -9` |
| `psexec.csv.xz` | the same Plaso storage, `psort.py -o dynamic`; compressed with `xz -9` |
| `recongraph-drain/`, `recongraph-sigma/` | ReconGraph `4ace7a0` on `psexec.jsonl`, `--node drain` and `--node sigma`, with the Windows rules of [`../README.md`](../README.md#versions); GraphML compressed with `xz -9` |

## Reproduce

```bash
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 \
  log2timeline.py --unattended --parsers winevtx --storage-file /data/psexec.plaso /data/psexec.evtx
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 psort.py -o json_line -w /data/psexec.jsonl /data/psexec.plaso
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 psort.py -o dynamic -w /data/psexec.csv /data/psexec.plaso
recongraph -f psexec.jsonl -r hayabusa-rules/sigma --exclude-status deprecated,unsupported \
  --exclude-rules-file hayabusa-rules/config/exclude_rules.txt --node drain -o recongraph-drain
recongraph -f psexec.jsonl -r hayabusa-rules/sigma --exclude-status deprecated,unsupported \
  --exclude-rules-file hayabusa-rules/config/exclude_rules.txt --node sigma -o recongraph-sigma
```

## Graphs

| Folder | Node mode | Rows read | Rows in graph | Nodes | Aggregate edges | Temporal edges |
|---|---|---|---|---|---|---|
| `recongraph-drain/` | drain | 10 | 10 | 5 | 8 | 9 |
| `recongraph-sigma/` | sigma | 10 | 4 | 3 | 3 | 3 |

*Rows read* are the rows of the timeline after loading: one per EVTX record (its creation time) and one per audit event. *Rows in graph* are all rows with `--node drain` and the rows with a Sigma label with `--node sigma`.
