# gus_alerting
Grafana, Uptime kuma and splunk alerting integration with SMS provider
# SMS Alerting Webhook Gateway

Single Flask process that receives alert webhooks from **Grafana**, **Uptime Kuma v2**,
and **Splunk** (alert action) and turns them into Farsi SMS via the SMS Provider gateway
(`sms.example.com`).

```
Grafana  ──POST──▶ /api/v2/alerts   ──┐
Uptime Kuma v2 ─POST─▶ /  or /api/v2/kuma ──┼──▶ send_sms() / send_sms_raw() ──▶ SMS Provider API
Splunk (webhook action) ─POST─▶ /api/v2/splunk ──┘
```

---

## 1. Endpoints

| Source        | Method | Path              | Notes |
|---------------|--------|-------------------|-------|
| Grafana       | POST   | `/api/v2/alerts`  | Expects Grafana's unified-alerting JSON (`alerts[].labels`, `.annotations.__value_string__`) |
| Uptime Kuma v2| POST   | `/` and `/api/v2/kuma` | Expects `{monitor:{name}, heartbeat:{status,msg}}`. Point Kuma's webhook notification at either path. |
| Splunk        | POST   | `/api/v2/splunk`  | Expects the native Splunk **Webhook alert action** payload: `{search_name, result:{...}, sid, ...}` |

---

## 2. Why Splunk is handled differently from Grafana/Kuma

Grafana (via Zabbix) and Uptime Kuma are **binary state machines** — a trigger/monitor
is either `OK` or `Problem`, and the webhook fires on the transition. `build_message()`
/ `remap_value()` encode that vocabulary (`Status: Problem` / `Status: OK`).

Splunk alert actions are **one-shot notices** — the scheduled search matched, full
stop. There's no "resolved" event to pair with it. Reusing the OK/Problem message
format for Splunk would be actively misleading (a firewall traffic log matching a
search isn't "in a Problem state"). So the Splunk path has its own:

- message builder: `build_message_splunk()` — no `item`/`value`/`Status` fields, just
  `Alert / Severity / <configured fields> / Time`.
- field source: the Splunk `result` object (the full log event), not Grafana/Kuma's
  `labels`/`annotations`/`monitor` schema.
- routing key for `phone.txt`: **configurable per alert type** (`host_field` in the
  config, see §3), because Splunk's own `result.host` is often the syslog relay IP
  (e.g. `172.31.0.10`), not the device you actually care about (e.g.
  `devname="FGT-300E-Master"`).

---

## 3. `splunk_fields.json` — declarative field extraction

```jsonc
{
  "match_field": "search_name",          // top-level key used to pick an alert def below
  "default_cooldown_minutes": 15,        // fallback if an alert def omits cooldown_minutes
  "max_sms_per_host_per_hour": 10,       // hard global cap, see §4

  "alerts": {
    "<search_name, case-insensitive>": {
      "display_name": "Human label shown in the SMS",
      "severity": "Info | Warning | Critical",   // free text, just interpolated
      "host_field": "devname",           // key inside result{} used for phone.txt routing
      "max_fields": 6,                   // cap on how many extracted fields go in the SMS
      "cooldown_minutes": 15,            // per-alert override of the burnout cooldown
      "dedup_extra_fields": ["srcip"],   // see §4 — widen the dedup key beyond host+alert
      "fields": [
        { "key": "srcip",  "label": "Src IP" },
        { "key": "dstip",  "label": "Dst IP" }
        // key = literal key inside Splunk's result{} object
        // label = what's printed in the SMS
        // missing/empty keys are silently skipped, not printed as "None"
      ]
    }
  },

  "default": { /* same shape, used when search_name matches nothing above */ }
}
```

**Hot reload:** the file's `mtime` is checked on every incoming Splunk alert
(`load_splunk_config()`), so you can edit field mappings and cooldowns without
restarting the process. No signal, no cron — just save the file.

**Value truncation:** any extracted field value longer than 60 chars is truncated with
`…`. This matters because Farsi/Unicode SMS segments are 70 chars — a message with too
many long fields silently becomes a multipart SMS (slower, sometimes billed per
segment). Keep `max_fields` tight (4–6) per alert type.

---

## 4. Burnout protection

Two independent gates, both must pass before an SMS actually goes out
(`check_burnout_protection()`):

### Gate 1 — per-alert cooldown (`(host, dedup_key)`)

`dedup_key` = `search_name` + any fields listed in `dedup_extra_fields`, pulled from
`result`. Examples:

- `"test"` alert with `dedup_extra_fields: []` → dedup key is just the alert type. Any
  repeat of that search on that host within `cooldown_minutes` is suppressed —
  regardless of which srcip/dstip triggered it.
- `"fortigate_ssh_bruteforce"` with `dedup_extra_fields: ["srcip"]` → dedup key includes
  the attacker IP. Repeated hits from `203.0.113.5` are suppressed after the first, but
  a *different* attacker IP `203.0.113.9` still gets its own SMS — you don't want two
  different attackers to suppress each other.

When a repeat is suppressed, it's **counted**, not dropped silently. The next SMS that
does go out for that `(host, dedup_key)` includes `(+N similar suppressed)` in the body,
so you know how noisy the condition was during the quiet window. Suppressions are
logged to `logs/sms_throttled.log` regardless (nothing is lost from an audit
standpoint — only the SMS itself is withheld).

### Gate 2 — global per-host cap (`max_sms_per_host_per_hour`)

Hard ceiling, independent of `dedup_key`. This is what actually stops a burnout
scenario where the noisy condition rotates its dedup key (e.g. a brute-force sweep
hitting from many different source IPs, each getting its own cooldown bucket) — gate 1
alone would let all of them through. Gate 2 caps total SMS/hour to a given host no
matter how many distinct alert types or dedup keys are involved. Checked *before* gate
1, so once the cap is hit, everything for that host is suppressed until the rolling
1-hour window clears.

### State

In-memory only (`_dedup_last_sent`, `_dedup_suppressed`, `_host_send_times`), guarded by
a single `threading.Lock`. Resets on process restart — acceptable for a long-running
daemon under systemd, but if you restart the service frequently or run multiple
instances behind a load balancer, this state needs to move to something shared
(Redis, sqlite) or you lose the cap's effectiveness. Flagging this now since it wasn't
in scope for this change but will bite you eventually.

### What this does NOT cover

Grafana and Uptime Kuma paths (`send_sms()`) have no burnout protection — they weren't
in scope for this pass, but a flapping Zabbix trigger or Kuma monitor can still page
you continuously.

---

## 5. Files

| File | Purpose |
|------|---------|
| `sms.py` | The Flask app. Run with `python3 sms.py` (dev) or behind gunicorn/systemd (prod, see §7). |
| `splunk_fields.json` | Splunk field-extraction + burnout config. Lives next to `sms.py`, read at startup and hot-reloaded on change. |
| `phone.txt` | host: phone1,phone2 lines for SMS routing. Falls back to `SMS_PHONE` constant if a host isn't listed. |

---

## 6. Logs (`logs/`)

| File | Content |
|------|---------|
| `logs/raw_alerts.log` | Every raw payload received on any endpoint, including malformed-JSON failures with full headers/body for debugging. |
| `logs/sms_sent.log` | Every SMS actually dispatched, with gateway HTTP response. |
| `logs/sms_throttled.log` | Every suppression event (cooldown or global cap), with reason and dedup key — this is your audit trail for "why didn't I get paged." |
| `logs/<host>/alerts.log` | Per-host alert log (one line per alert processed, sent or suppressed). |

