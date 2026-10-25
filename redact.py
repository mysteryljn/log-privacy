#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
from pathlib import Path
def pseudonym(value,secret):
    return "p_"+hmac.new(secret.encode(),str(value).encode(),hashlib.sha256).hexdigest()[:16]
def redact(record,secret,drop_gps=True):
    result=dict(record)
    for key in ("vin","user_id","driver_id"):
        if key in result: result[key]=pseudonym(result[key],secret)
    if drop_gps:
        result.pop("gps",None); result.pop("latitude",None); result.pop("longitude",None)
    if "timestamp" in result: result["timestamp_bucket"]=int(float(result.pop("timestamp"))//60)*60
    if "can_id" in result: result["can_id"]=int(result["can_id"],0) if isinstance(result["can_id"],str) else result["can_id"]
    return result
def process(lines,secret,drop_gps=True):
    for line in lines:
        if line.strip(): yield redact(json.loads(line),secret,drop_gps)
def main(argv=None):
    p=argparse.ArgumentParser(description="Redact sensitive fields from JSONL vehicle logs"); p.add_argument("input",type=Path); p.add_argument("output",type=Path); p.add_argument("--secret",required=True); p.add_argument("--keep-gps",action="store_true"); a=p.parse_args(argv)
    with a.output.open("w",encoding="utf-8") as out:
        for item in process(a.input.read_text(encoding="utf-8").splitlines(),a.secret,not a.keep_gps): out.write(json.dumps(item,ensure_ascii=False)+"\n")
    return 0
if __name__=="__main__": raise SystemExit(main())
