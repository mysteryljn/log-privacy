#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
from pathlib import Path


# Keys are compared in canonical form so producers can use snake_case,
# kebab-case, camelCase, or all-uppercase spellings without bypassing
# redaction.
_SENSITIVE_KEYS = {"vin", "userid", "driverid"}
_GPS_KEYS = {"gps", "latitude", "longitude"}


def pseudonym(value,secret):
    return "p_"+hmac.new(secret.encode(),str(value).encode(),hashlib.sha256).hexdigest()[:16]


def _canonical_key(key):
    if not isinstance(key, str):
        return key
    return "".join(ch for ch in key.casefold() if ch.isalnum())


def _bucket_timestamp(value):
    return int(float(value)//60)*60


def _normalize_can_id(value):
    return int(value,0) if isinstance(value,str) else value


def _redact_value(value, secret, drop_gps):
    """Redact sensitive fields at every level of a JSON log record.

    Vehicle logs commonly wrap the actual event in a ``payload`` or an
    array of events.  Walking mappings and lists prevents those wrappers
    from becoming a way to bypass the top-level privacy rules.
    """
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            # Keep the existing field names and matching semantics; this
            # fix extends them into nested mappings and lists.
            normalized_key = _canonical_key(key)
            if drop_gps and normalized_key in _GPS_KEYS:
                continue
            if normalized_key in _SENSITIVE_KEYS:
                result[key] = pseudonym(item, secret)
            elif normalized_key == "timestamp":
                result["timestamp_bucket"] = _bucket_timestamp(item)
            elif normalized_key == "can_id":
                result[key] = _normalize_can_id(item)
            else:
                result[key] = _redact_value(item, secret, drop_gps)
        # Match the original top-level behavior when an input already has a
        # timestamp_bucket: the computed bucket always wins.
        if "timestamp" in value:
            result["timestamp_bucket"] = _bucket_timestamp(value["timestamp"])
        return result
    if isinstance(value, list):
        return [_redact_value(item, secret, drop_gps) for item in value]
    return value


def redact(record,secret,drop_gps=True):
    return _redact_value(record, secret, drop_gps)


def process(lines,secret,drop_gps=True):
    for line in lines:
        if line.strip(): yield redact(json.loads(line),secret,drop_gps)
def main(argv=None):
    p=argparse.ArgumentParser(description="Redact sensitive fields from JSONL vehicle logs"); p.add_argument("input",type=Path); p.add_argument("output",type=Path); p.add_argument("--secret",required=True); p.add_argument("--keep-gps",action="store_true"); a=p.parse_args(argv)
    with a.output.open("w",encoding="utf-8") as out:
        for item in process(a.input.read_text(encoding="utf-8").splitlines(),a.secret,not a.keep_gps): out.write(json.dumps(item,ensure_ascii=False)+"\n")
    return 0
if __name__=="__main__": raise SystemExit(main())
