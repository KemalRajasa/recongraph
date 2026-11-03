# Plaso JSONL fixtures

Cut (whole lines, unchanged) from `psort -o json_line` output of log2timeline/plaso:20260720 run on files from
[Plaso](https://github.com/log2timeline/plaso) `test_data/` at tag 20260720 (commit 4ea03ef9a48dad5284c371ac9b537a184b3eea9c),
licensed Apache-2.0.

| fixture | Plaso test_data file |
|---|---|
| linux_auth.jsonl, filestat.jsonl | syslog/syslog_ssh.log, saved as auth.log |
| linux_syslog.jsonl | syslog/syslog |
| linux_syslog_gz.jsonl | syslog.gz |
| android_logcat.jsonl | android_logcat.log |
| android_sms.jsonl | android/mmssms.db |
| android_calls.jsonl | android/contacts2.db |
| ios_lockdownd.jsonl | ios_lockdownd.log |
| ios_sysdiag.jsonl | ios_sysdiag.log |
| ios_logd.jsonl | logd.0.log |
| filestat_image_dir.jsonl | syslog_image.dd |

`winevtx_golden_e9b07b9.json`: the winevtx rows of `../plaso_sample.jsonl`, `../sysmon_lsass.jsonl` and
`../eventlog_cleared.jsonl` as loaded by the adapter at commit e9b07b9.
