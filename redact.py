#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import math
import sys
from pathlib import Path


# Keys are compared in canonical form so producers can use snake_case,
# kebab-case, camelCase, or all-uppercase spellings without bypassing
# redaction.
# Identity-bearing contact fields are also sensitive in shared vehicle logs.
# The keys are stored in canonical form; ``emailAddress`` and
# ``phone_number`` therefore match without maintaining spelling variants.
_SENSITIVE_KEYS = {
    "vin",
    "userid",
    "driverid",
    "email",
    "emailaddress",
    "phone",
    "phonenumber",
    "mobile",
    "mobilephone",
}
# Vehicle log producers use both full coordinate names and compact CAN-facing
# aliases.  Canonicalization below makes these checks case/separator agnostic,
# so this set contains the canonical forms (for example ``gpsLat`` becomes
# ``gpslat``).  Missing an alias here would leave a precise coordinate in a
# supposedly redacted record.
_GPS_KEYS = {
    "gps",
    "latitude",
    "longitude",
    "lat",
    "lon",
    "lng",
    "gpslatitude",
    "gpslongitude",
    "gpslat",
    "gpslon",
    "gpslng",
    "location",
    "coordinates",
}


def pseudonym(value,secret):
    return "p_"+hmac.new(secret.encode(),str(value).encode(),hashlib.sha256).hexdigest()[:16]


def _canonical_key(key):
    if not isinstance(key, str):
        return key
    return "".join(ch for ch in key.casefold() if ch.isalnum())


def _bucket_timestamp(value):
    # Logs can contain a malformed timestamp (or JSON ``null``).  Letting the
    # conversion exception escape aborts processing of the entire JSONL file,
    # while copying the original value would defeat timestamp coarsening.  A
    # null bucket keeps the output schema stable without leaking the input.
    if isinstance(value, bool):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(numeric):
        return None
    return int(numeric // 60) * 60


def _normalize_can_id(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            return int(value, 0)
        except (TypeError, ValueError, OverflowError):
            # Keep one malformed log field from aborting an entire privacy
            # export.  ``None`` makes the invalid value explicit without
            # passing the original token through to downstream tooling.
            return None
    return value if isinstance(value, int) else None


def _redact_value(value, secret, drop_gps):
    """Redact sensitive fields at every level of a JSON log record.

    Vehicle logs commonly wrap the actual event in a ``payload`` or an
    array of events.  Walking mappings and lists prevents those wrappers
    from becoming a way to bypass the top-level privacy rules.
    """
    if isinstance(value, dict):
        result = {}
        # A pre-existing timestamp_bucket must not overwrite a bucket
        # calculated from any timestamp spelling (for example ``timeStamp``).
        # Determine this before walking the mapping so the result does not
        # depend on input key order.
        has_timestamp = any(_canonical_key(key) == "timestamp" for key in value)
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
            # ``_canonical_key`` removes separators, so ``can_id`` becomes
            # ``canid``.  Comparing against the underscored spelling made
            # this branch unreachable and left every CAN ID as a string.
            elif normalized_key == "canid":
                result[key] = _normalize_can_id(item)
            elif normalized_key == "timestampbucket" and has_timestamp:
                # The bucket derived from the timestamp is authoritative;
                # dropping the input value prevents a precise bucket from
                # bypassing timestamp coarsening.
                continue
            else:
                result[key] = _redact_value(item, secret, drop_gps)
        return result
    if isinstance(value, list):
        return [_redact_value(item, secret, drop_gps) for item in value]
    return value


def redact(record,secret,drop_gps=True):
    return _redact_value(record, secret, drop_gps)


def process(lines,secret,drop_gps=True):
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            # A malformed JSONL record must fail closed.  Letting the parser
            # exception escape produces a traceback and hides which input
            # record needs repair, while silently skipping it would lose log
            # evidence without an audit trail.
            raise ValueError(
                f"invalid JSON on input line {line_number}: {exc.msg}"
            ) from exc
        yield redact(record,secret,drop_gps)
def main(argv=None):
    p=argparse.ArgumentParser(description="Redact sensitive fields from JSONL vehicle logs"); p.add_argument("input",type=Path); p.add_argument("output",type=Path); p.add_argument("--secret",required=True); p.add_argument("--keep-gps",action="store_true"); a=p.parse_args(argv)
    try:
        with a.input.open("r",encoding="utf-8") as source, a.output.open("w",encoding="utf-8") as out:
            for item in process(source,a.secret,not a.keep_gps):
                out.write(json.dumps(item,ensure_ascii=False)+"\n")
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
