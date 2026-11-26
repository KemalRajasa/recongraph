# windows_sideload

Malware execution that combines several techniques; the source names it after DLL side-loading, a UAC bypass, rundll32 injection and C2. Sysmon, 18 records.

## Source and license

`sideload.evtx` is `AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx` from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by
sbousseaden (uploaded 2020-10-17, repository commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`), unchanged:

```
SHA-256 ead8a4c6c822da22ac98c6f16123090f0eb30955666c63f9acaa0d51561925da
```

EVTX-ATTACK-SAMPLES is licensed under the GNU General Public License v3.0, included as [`LICENSE.GPL`](LICENSE.GPL).
**Every file in this folder is distributed under GPL-3.0**, the files derived from `sideload.evtx` included; the rest
of the ReconGraph repository is MIT licensed.

## Modified

The other files of this folder were derived from `sideload.evtx` (date of this version: 2026-11-26):

| File | How |
|---|---|
| `sideload.jsonl.xz` | `log2timeline.py --parsers winevtx`, then `psort.py -o json_line`; Plaso 20261027; compressed with `xz -9` |
| `sideload.csv.xz` | the same Plaso storage, `psort.py -o dynamic`; compressed with `xz -9` |
| `recongraph-drain/`, `recongraph-sigma/` | ReconGraph `4ace7a0` on `sideload.jsonl`, `--node drain` and `--node sigma`, with the Windows rules of [`../README.md`](../README.md#versions); GraphML compressed with `xz -9` |

## Reproduce

```bash
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 \
  log2timeline.py --unattended --parsers winevtx --storage-file /data/sideload.plaso /data/sideload.evtx
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 psort.py -o json_line -w /data/sideload.jsonl /data/sideload.plaso
docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 psort.py -o dynamic -w /data/sideload.csv /data/sideload.plaso
recongraph -f sideload.jsonl -r hayabusa-rules/sigma --exclude-status deprecated,unsupported \
  --exclude-rules-file hayabusa-rules/config/exclude_rules.txt --node drain -o recongraph-drain
recongraph -f sideload.jsonl -r hayabusa-rules/sigma --exclude-status deprecated,unsupported \
  --exclude-rules-file hayabusa-rules/config/exclude_rules.txt --node sigma -o recongraph-sigma
```

## Graphs

| Folder | Node mode | Rows read | Rows in graph | Nodes | Aggregate edges | Temporal edges |
|---|---|---|---|---|---|---|
| `recongraph-drain/` | drain | 18 | 18 | 4 | 8 | 17 |
| `recongraph-sigma/` | sigma | 18 | 15 | 8 | 12 | 14 |

*Rows read* are the rows of the timeline after loading: one per EVTX record (its creation time) and one per audit event. *Rows in graph* are all rows with `--node drain` and the rows with a Sigma label with `--node sigma`.
