#!/usr/bin/env python3
import os
import re
import json
import logging
import threading
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from logging.handlers import TimedRotatingFileHandler
from flask import Flask, request, jsonify
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

app = Flask(__name__)

# ----------------------------------------------------------------------
# 1. GLOBAL SESSION (relaxed ciphers for self-signed gateway cert)
# ----------------------------------------------------------------------
session = requests.Session()


class InsecureSSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context(ciphers='DEFAULT:!DH:!DHE')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


session.mount('https://', InsecureSSLAdapter())

# ----------------------------------------------------------------------
# 2. CONFIG
# ----------------------------------------------------------------------
SMS_GATEWAY = 'https://sms.example.com/send.ashx'
SMS_USERNAME = 'username'
SMS_PASSWORD = 'password'
SMS_FROM     = '111111111'
SMS_PHONE    = '222222222'  # fallback if host not in phone.txt

# ----------------------------------------------------------------------
# 3. PHONE MAPPING - supports multiple phones per host
# ----------------------------------------------------------------------
PHONE_FILE = 'phone.txt'
host_phones = {}

if os.path.exists(PHONE_FILE):
    with open(PHONE_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if ':' in line and not line.startswith('#'):
                host_part, phones_part = line.split(':', 1)
                host = host_part.strip().lower()
                phones = [p.strip().lstrip('+') for p in phones_part.split(',') if p.strip()]
                host_phones[host] = phones
    total = sum(len(v) for v in host_phones.values())
    print(f"Loaded {total} phone numbers for {len(host_phones)} hosts from {PHONE_FILE}")
else:
    print(f"Warning: {PHONE_FILE} not found - using default phone {SMS_PHONE}")

# ----------------------------------------------------------------------
# 3b. SPLUNK FIELD-EXTRACTION CONFIG (declarative, hot-reloadable)
# ----------------------------------------------------------------------
SPLUNK_CONFIG_FILE = 'splunk_fields.json'
splunk_config = {}
splunk_config_mtime = 0
splunk_config_lock = threading.Lock()

DEFAULT_SPLUNK_FALLBACK = {
    "display_name": "Splunk Alert",
    "severity": "Warning",
    "host_field": "host",
    "max_fields": 5,
    "cooldown_minutes": 15,
    "dedup_extra_fields": [],
    "fields": [{"key": "host", "label": "Host"}],
}


def load_splunk_config(force=False):
    """Load splunk_fields.json. Re-reads automatically if the file's mtime
    changed, so field mappings can be edited without restarting the process."""
    global splunk_config, splunk_config_mtime
    if not os.path.exists(SPLUNK_CONFIG_FILE):
        with splunk_config_lock:
            splunk_config = {
                "match_field": "search_name",
                "default_cooldown_minutes": 15,
                "max_sms_per_host_per_hour": 10,
                "alerts": {},
                "default": DEFAULT_SPLUNK_FALLBACK,
            }
        print(f"Warning: {SPLUNK_CONFIG_FILE} not found - using minimal default Splunk config")
        return

    mtime = os.path.getmtime(SPLUNK_CONFIG_FILE)
    if not force and mtime == splunk_config_mtime:
        return

    with open(SPLUNK_CONFIG_FILE, 'r', encoding='utf-8') as f:
        cfg = json.load(f)

    with splunk_config_lock:
        splunk_config = cfg
        splunk_config_mtime = mtime

    print(f"Loaded Splunk alert config: {len(cfg.get('alerts', {}))} alert definitions "
          f"(match_field={cfg.get('match_field', 'search_name')}, "
          f"max_sms_per_host_per_hour={cfg.get('max_sms_per_host_per_hour', 10)})")


load_splunk_config(force=True)

# ----------------------------------------------------------------------
# 4. LOGGING
# ----------------------------------------------------------------------
os.makedirs('logs', exist_ok=True)

raw_logger = logging.getLogger('raw_alerts')
raw_logger.setLevel(logging.INFO)
raw_handler = TimedRotatingFileHandler('logs/raw_alerts.log', when='midnight', interval=1, backupCount=7, encoding='utf-8')
raw_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
raw_logger.addHandler(raw_handler)
raw_logger.propagate = False

sms_logger = logging.getLogger('sms_sent')
sms_logger.setLevel(logging.INFO)
sms_handler = TimedRotatingFileHandler('logs/sms_sent.log', when='midnight', interval=1, backupCount=7, encoding='utf-8')
sms_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
sms_logger.addHandler(sms_handler)
sms_logger.propagate = False

# separate logger just for burnout-protection suppressions, so you can audit
# "what got swallowed" without grepping the SMS log for negative matches
throttle_logger = logging.getLogger('sms_throttled')
throttle_logger.setLevel(logging.INFO)
throttle_handler = TimedRotatingFileHandler('logs/sms_throttled.log', when='midnight', interval=1, backupCount=7, encoding='utf-8')
throttle_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
throttle_logger.addHandler(throttle_handler)
throttle_logger.propagate = False


def get_logger(host):
    logger = logging.getLogger(host)
    if not logger.handlers:
        log_dir = f"logs/{host}"
        os.makedirs(log_dir, exist_ok=True)
        h = TimedRotatingFileHandler(os.path.join(log_dir, 'alerts.log'), when='midnight', interval=1, backupCount=7, encoding='utf-8')
        h.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


# ----------------------------------------------------------------------
# 5. HELPERS - shared
# ----------------------------------------------------------------------
def truncate_ns(ts: str) -> str:
    """Trim nanosecond timestamps to microseconds so fromisoformat() can parse them.
    e.g. '2026-06-04T22:56:44.956230675+00:00' -> '2026-06-04T22:56:44.956230+00:00'
    """
    return re.sub(r'(\.\d{6})\d+', r'\1', ts)


def parse_value_string(vs):
    if not vs:
        return None
    try:
        vs = vs.strip()
        part = vs.split('value=', 1)[1]
        cur = part.split(' ', 1)[0].rstrip('],').strip()
        return float(cur) if '.' in cur else int(cur)
    except Exception:
        return None


def remap_value(v):
    if v == 0:
        return 'Problem'
    if v == 1:
        return 'OK'
    return str(v)


def get_host_phones(host):
    phones = host_phones.get(host.lower(), [])
    return phones or [SMS_PHONE.lstrip('+')]


def build_message(host, item, value, date_str):
    """Grafana/Kuma-only: these two sources are binary OK<->Problem state
    machines (Zabbix triggers, uptime checks). Do NOT reuse this for Splunk -
    Splunk alerts are one-shot notices, not state transitions."""
    status = remap_value(value)
    return (
        f"هشدار مانیتورینگ\n"
        f"Host: {host}\n"
        f"Item: {item}\n"
        f"Status: {status}\n"
        f"Time: {date_str}"
    )


def send_sms_raw(host, message, log_ctx=""):
    """Low-level sender: takes a fully-built message body and blasts it to
    every phone mapped to `host` in phone.txt. Shared by all alert sources."""
    phones = get_host_phones(host)
    for phone in phones:
        params = {
            'username': SMS_USERNAME,
            'password': SMS_PASSWORD,
            'from':     SMS_FROM,
            'to':       phone,
            'farsi':    'true',
            'message':  message,
        }
        sms_logger.info(f"SEND → {phone} | host={host} {log_ctx}")
        try:
            r = session.get(SMS_GATEWAY, params=params, timeout=15, verify=False)
            sms_logger.info(f"SMS RESPONSE {phone} → {r.status_code} – {r.text}")
            if 200 <= r.status_code < 300:
                print(f"SMS sent to {phone}")
            else:
                print(f"SMS failed to {phone}: {r.status_code} – {r.text}")
        except Exception as e:
            sms_logger.exception(f"SMS exception to {phone}: {e}")


def send_sms(host, item, value, date_str):
    """Grafana/Kuma-style sender: builds the OK/Problem message then delegates
    to send_sms_raw. NOT used by the Splunk path."""
    message = build_message(host, item, value, date_str)
    send_sms_raw(host, message, log_ctx=f"item={item} value={value}")


def send_sms_async(host, message, log_ctx=""):
    """Fire-and-forget dispatch so the Flask handler can ACK the caller
    (Splunk's webhook alert action has a short timeout) before the SMS
    gateway round-trip completes."""
    t = threading.Thread(target=send_sms_raw, args=(host, message, log_ctx), daemon=True)
    t.start()


def now_tehran():
    return datetime.now(ZoneInfo("Asia/Tehran"))


def now_tehran_str():
    return now_tehran().strftime('%Y-%m-%d %H:%M Tehran')


def extract_json_from_raw_body(raw_body):
    """Defensive JSON extraction for payloads that may arrive with leading
    junk bytes ahead of the '{' (seen on some HTTP client / proxy configs).
    Slices from the first '{' to the last '}' and attempts a parse."""
    start_idx = raw_body.index('{')
    end_idx = raw_body.rindex('}') + 1
    return json.loads(raw_body[start_idx:end_idx])


def is_splunk_shaped(data):
    """Signature check for a Splunk alert-action payload: it always has a
    'result' object, and virtually always a 'search_name' + 'sid'. Used as a
    safety net on the Kuma routes in case the Splunk alert action's URL is
    misconfigured to point at '/' instead of '/api/v2/splunk'."""
    return isinstance(data, dict) and isinstance(data.get('result'), dict) and (
        'search_name' in data or 'sid' in data
    )


# ----------------------------------------------------------------------
# 5b. SPLUNK-SPECIFIC LOGIC (fully decoupled from Grafana/Kuma)
# ----------------------------------------------------------------------
# Splunk alert actions fire once per scheduled-search match - there is no
# "OK" transition to pair it with, unlike a Zabbix trigger or an uptime
# check. So this path never uses build_message()/remap_value()/item/value
# vocabulary. It also gets its own burnout protection since a noisy
# correlation search (e.g. running every minute) can otherwise page you
# continuously for the same underlying condition.

_burnout_lock = threading.Lock()
_dedup_last_sent = {}     # {(host, dedup_key): datetime of last SMS actually sent}
_dedup_suppressed = {}    # {(host, dedup_key): count suppressed since last SMS}
_host_send_times = {}     # {host: [datetime, ...]} rolling log for the global cap


def get_alert_definition(match_value):
    """Look up the alert definition for the given search_name (or whatever
    match_field points to), case-insensitively. Falls back to 'default'."""
    load_splunk_config()  # cheap mtime check, reloads if file changed on disk
    with splunk_config_lock:
        alerts = splunk_config.get('alerts', {})
        default = dict(DEFAULT_SPLUNK_FALLBACK)
        default.update(splunk_config.get('default', {}))
        cooldown_default = splunk_config.get('default_cooldown_minutes', 15)
        global_cap = splunk_config.get('max_sms_per_host_per_hour', 10)

    match_key = (match_value or '').strip().lower()
    for name, definition in alerts.items():
        if name.strip().lower() == match_key:
            merged = dict(default)
            merged.update(definition)
            merged.setdefault('cooldown_minutes', cooldown_default)
            merged['_global_cap'] = global_cap
            return merged

    default.setdefault('cooldown_minutes', cooldown_default)
    default['_global_cap'] = global_cap
    return default


def extract_splunk_fields(result, field_defs, max_field_value_len=60):
    """Pull the configured keys out of the Splunk result dict, in config
    order. Skips missing/empty fields. Truncates long values (e.g. raw URLs)
    to keep the SMS from ballooning into many segments."""
    extracted = []
    for fd in field_defs:
        key = fd.get('key')
        label = fd.get('label', key)
        val = result.get(key)
        if val in (None, ''):
            continue
        val = str(val)
        if len(val) > max_field_value_len:
            val = val[:max_field_value_len] + '…'
        extracted.append((label, val))
    return extracted


def build_message_splunk(display_name, severity, extracted_fields, date_str, suppressed_count=0):
    lines = [
        "هشدار Splunk",
        f"Alert: {display_name}",
        f"Severity: {severity}",
    ]
    for label, val in extracted_fields:
        lines.append(f"{label}: {val}")
    if suppressed_count > 0:
        lines.append(f"(+{suppressed_count} similar suppressed)")
    lines.append(f"Time: {date_str}")
    return "\n".join(lines)


def check_burnout_protection(host, dedup_key, cooldown_minutes, global_cap):
    """Decides whether an SMS should actually go out for this alert.

    Two independent gates, both must pass:
      1. Per-(host, dedup_key) cooldown - the same alert type (optionally
         scoped further by dedup_extra_fields, e.g. per source IP) is only
         allowed to page once per cooldown_minutes. Repeats within the
         window are counted, not sent, and the count is folded into the next
         SMS that does go out ("+N similar suppressed").
      2. Global per-host rate cap - hard ceiling on total SMS/hour to a given
         host regardless of how many distinct alert types are firing. This
         is what actually stops a burnout scenario (e.g. a broad correlation
         search matching many different source IPs every minute, which would
         otherwise bypass the per-key cooldown by rotating dedup_key).

    Returns (allowed: bool, suppressed_count_to_report: int, reason: str)
    """
    now = now_tehran()
    with _burnout_lock:
        # --- gate 2: global per-host cap (checked first, it's the hard stop) ---
        window_start = now - timedelta(hours=1)
        times = [t for t in _host_send_times.get(host, []) if t > window_start]
        _host_send_times[host] = times
        if len(times) >= global_cap:
            key = (host, dedup_key)
            _dedup_suppressed[key] = _dedup_suppressed.get(key, 0) + 1
            return False, 0, f"global_cap ({global_cap}/hr reached for host={host})"

        # --- gate 1: per-alert cooldown ---
        key = (host, dedup_key)
        last_sent = _dedup_last_sent.get(key)
        if last_sent is not None and (now - last_sent) < timedelta(minutes=cooldown_minutes):
            _dedup_suppressed[key] = _dedup_suppressed.get(key, 0) + 1
            return False, 0, f"cooldown ({cooldown_minutes}m, key={dedup_key})"

        # allowed - reset counters and record the send
        suppressed = _dedup_suppressed.pop(key, 0)
        _dedup_last_sent[key] = now
        _host_send_times.setdefault(host, []).append(now)
        return True, suppressed, "ok"


def process_splunk_alert(data):
    """Core Splunk alert-action handler. Returns (response_dict, http_status).
    Called from /api/v2/splunk directly, and defensively from the Kuma
    routes if a Splunk-shaped payload lands there by mistake."""
    match_field = splunk_config.get('match_field', 'search_name')
    match_value = data.get(match_field, '')
    result = data.get('result', {}) or {}

    alert_def = get_alert_definition(match_value)
    display_name = alert_def.get('display_name', match_value or 'Splunk Alert')
    severity = alert_def.get('severity', 'Warning')
    host_field = alert_def.get('host_field', 'host')
    field_defs = alert_def.get('fields', [])
    max_fields = alert_def.get('max_fields', 5)
    cooldown_minutes = alert_def.get('cooldown_minutes', 15)
    global_cap = alert_def.get('_global_cap', 10)
    dedup_extra_fields = alert_def.get('dedup_extra_fields', [])

    # host resolution: prefer the field named by host_field inside `result`,
    # fall back to top-level `host`, then a hardcoded default so phone.txt
    # lookup never explodes on a malformed payload.
    host = result.get(host_field) or data.get('host') or 'unknown_host'

    extracted = extract_splunk_fields(result, field_defs)[:max_fields]
    date_str = now_tehran_str()

    # dedup key = alert type + host + any extra discriminating fields
    # (e.g. attacker srcip for brute-force alerts, so distinct attackers
    # don't suppress each other while repeats from the same one do)
    dedup_parts = [str(match_value).lower()]
    for f in dedup_extra_fields:
        dedup_parts.append(str(result.get(f, '')))
    dedup_key = "|".join(dedup_parts)

    summary = "; ".join(f"{k}={v}" for k, v in extracted) or "no fields matched config"
    get_logger(host).info(f"{display_name} ALERT on {host} ({summary}) at {date_str}")

    allowed, suppressed_count, reason = check_burnout_protection(host, dedup_key, cooldown_minutes, global_cap)

    if not allowed:
        throttle_logger.info(f"SUPPRESSED host={host} alert={display_name} dedup_key={dedup_key} reason={reason}")
        return {
            'status': 'suppressed',
            'reason': reason,
            'alert': display_name,
            'host': host,
        }, 200

    message = build_message_splunk(display_name, severity, extracted, date_str, suppressed_count)

    # async: Splunk's webhook alert action times out quickly, don't make it
    # wait on the SMS gateway round-trip
    send_sms_async(host, message, log_ctx=f"splunk_alert={display_name} dedup_key={dedup_key}")

    return {
        'status': 'ok',
        'alert': display_name,
        'host': host,
        'fields_extracted': len(extracted),
        'suppressed_count_included': suppressed_count,
    }, 200


# ----------------------------------------------------------------------
# 6. FLASK ENDPOINTS
# ----------------------------------------------------------------------

# --- GRAFANA ---
@app.route('/api/v2/alerts', methods=['POST'])
def handle_alert():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON'}), 400

        raw_logger.info(json.dumps(data, indent=2, default=str))

        alerts = data if isinstance(data, list) else data.get('alerts', data.get('evalMatches', []))
        if not alerts:
            return jsonify({'status': 'ok'}), 200

        processed = 0
        for a in alerts:
            if not isinstance(a, dict):
                continue

            lbl = a.get('labels', {})
            ann = a.get('annotations', {})
            start = a.get('startsAt', datetime.utcnow().isoformat())

            host = lbl.get('host') or 'unknown_host'
            item = lbl.get('item', lbl.get('alertname', 'unknown_item'))
            val_str = ann.get('__value_string__', '')
            val = parse_value_string(val_str)
            if val is None:
                continue

            try:
                dt_utc = datetime.fromisoformat(truncate_ns(start).replace('Z', '+00:00'))
                dt_tehran = dt_utc.astimezone(ZoneInfo("Asia/Tehran"))
                date_str = dt_tehran.strftime('%Y-%m-%d %H:%M Tehran')
            except Exception:
                date_str = start[:16] + ' Tehran'

            get_logger(host).info(f"{item} ALERT on {host} (value:{val}) at {date_str}")
            send_sms(host, item, val, date_str)
            processed += 1

        return jsonify({'status': 'ok', 'processed': processed}), 200

    except Exception as e:
        sms_logger.exception("handle_alert error")
        return jsonify({'error': str(e)}), 500


# --- UPTIME KUMA v2 (with Splunk-payload safety net) ---
@app.route('/', methods=['POST'])
@app.route('/api/v2/kuma', methods=['POST'])
def handle_kuma():
    try:
        data = request.get_json(force=True, silent=True)

        if not data:
            raw_body = request.get_data(as_text=True)
            raw_logger.error(f"KUMA RAW FAILURE. Headers: {dict(request.headers)} | Body: {raw_body}")
            try:
                data = extract_json_from_raw_body(raw_body)
            except Exception:
                return jsonify({'status': 'ignored', 'reason': 'Invalid JSON format'}), 200

        # Safety net: if a Splunk-shaped payload lands on the Kuma route
        # (e.g. the Splunk webhook alert action URL was set to the bare
        # root instead of /api/v2/splunk), don't let it fall through to
        # Kuma's monitor/heartbeat parsing - it'll just default to
        # "Unknown_Monitor" / "No details available" and produce a
        # meaningless SMS. Route it to the real Splunk handler instead and
        # log loudly so the misconfiguration gets fixed at the source.
        if is_splunk_shaped(data):
            raw_logger.warning(
                "Splunk-shaped payload received on Kuma route "
                f"({request.path}) - check the Splunk webhook alert action "
                "URL, it should point to /api/v2/splunk. Processing via "
                "Splunk logic this time so no alert is lost."
            )
            resp, status = process_splunk_alert(data)
            return jsonify(resp), status

        raw_logger.info(f"KUMA RAW SUCCESS: {json.dumps(data)}")

        monitor = data.get('monitor') or {}
        heartbeat = data.get('heartbeat') or {}

        host = monitor.get('name') or 'Unknown_Monitor'
        details = heartbeat.get('msg') or data.get('msg') or 'No details available'
        item = f"Status: {details}"

        status_val = heartbeat.get('status')
        value = 1 if status_val == 1 else 0

        date_str = now_tehran_str()

        get_logger(host).info(f"{item} ALERT on {host} (value:{value}) at {date_str}")
        send_sms(host, item, value, date_str)

        return jsonify({'status': 'ok'}), 200

    except Exception as e:
        sms_logger.exception("handle_kuma error")
        return jsonify({'error': str(e)}), 500


# --- SPLUNK ALERT ACTION (webhook) ---
@app.route('/api/v2/splunk', methods=['POST'])
def handle_splunk():
    try:
        data = request.get_json(force=True, silent=True)

        if not data:
            raw_body = request.get_data(as_text=True)
            raw_logger.error(f"SPLUNK RAW FAILURE. Headers: {dict(request.headers)} | Body: {raw_body}")
            try:
                data = extract_json_from_raw_body(raw_body)
            except Exception:
                return jsonify({'status': 'ignored', 'reason': 'Invalid JSON format'}), 200

        raw_logger.info(f"SPLUNK RAW SUCCESS: {json.dumps(data, default=str)}")

        resp, status = process_splunk_alert(data)
        return jsonify(resp), status

    except Exception as e:
        sms_logger.exception("handle_splunk error")
        return jsonify({'error': str(e)}), 500


# ----------------------------------------------------------------------
# 7. ENTRYPOINT
# ----------------------------------------------------------------------
if __name__ == '__main__':
    print("SMS webhook v5 ready - Grafana(/api/v2/alerts) + Kuma(/api/v2/kuma, /) + Splunk(/api/v2/splunk, with burnout protection) - listening on port 8068 (Tehran time)")
    app.run(host='0.0.0.0', port=8068, debug=False)
