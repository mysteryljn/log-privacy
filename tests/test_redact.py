import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory

from redact import main, redact
class RedactTests(unittest.TestCase):
    def test_sensitive_fields(self):
        result=redact({"timestamp":121,"vin":"VIN","gps":{"lat":1},"user_id":"u"},"secret")
        self.assertTrue(result["vin"].startswith("p_")); self.assertNotIn("gps",result); self.assertEqual(result["timestamp_bucket"],120)
    def test_stable_pseudonym(self):
        self.assertEqual(redact({"vin":"V"},"s")["vin"],redact({"vin":"V"},"s")["vin"])

    def test_nested_sensitive_fields_are_redacted(self):
        result = redact({
            "payload": {
                "vin": "nested-vin",
                "user_id": "nested-user",
                "gps": {"lat": 31.2, "lon": 121.5},
            },
            "events": [{"driver_id": "nested-driver", "latitude": 31.2}],
        }, "secret")

        self.assertTrue(result["payload"]["vin"].startswith("p_"))
        self.assertTrue(result["payload"]["user_id"].startswith("p_"))
        self.assertNotIn("gps", result["payload"])
        self.assertTrue(result["events"][0]["driver_id"].startswith("p_"))
        self.assertNotIn("latitude", result["events"][0])

    def test_sensitive_key_spelling_variants_are_redacted(self):
        result = redact({
            "VIN": "uppercase-vin",
            "USER-ID": "hyphen-user",
            "driverId": "camel-driver",
            "GPS": {"lat": 31.2, "lon": 121.5},
            "LaTiTuDe": 31.2,
            "LONGITUDE": 121.5,
        }, "secret")

        self.assertTrue(result["VIN"].startswith("p_"))
        self.assertTrue(result["USER-ID"].startswith("p_"))
        self.assertTrue(result["driverId"].startswith("p_"))
        self.assertNotIn("GPS", result)
        self.assertNotIn("LaTiTuDe", result)
        self.assertNotIn("LONGITUDE", result)

    def test_compact_coordinate_aliases_are_redacted_recursively(self):
        # Compact aliases are common in decoded CAN logs and used to bypass
        # the original latitude/longitude-only filter.
        result = redact({
            "lat": 31.2,
            "lon": 121.5,
            "events": [{"gpsLat": 31.2, "gpsLon": 121.5, "LNG": 121.5}],
        }, "secret")

        self.assertNotIn("lat", result)
        self.assertNotIn("lon", result)
        self.assertNotIn("gpsLat", result["events"][0])
        self.assertNotIn("gpsLon", result["events"][0])
        self.assertNotIn("LNG", result["events"][0])

    def test_contact_pii_aliases_are_pseudonymized_recursively(self):
        # Contact details are common in driver/session metadata and must not
        # bypass the existing user/driver identifier rules.
        result = redact({
            "session": {
                "emailAddress": "driver@example.com",
                "phone_number": "+8613800138000",
                "events": [{"mobilePhone": "+8613900139000"}],
            },
        }, "secret")

        self.assertTrue(result["session"]["emailAddress"].startswith("p_"))
        self.assertTrue(result["session"]["phone_number"].startswith("p_"))
        self.assertTrue(result["session"]["events"][0]["mobilePhone"].startswith("p_"))

    def test_can_id_is_normalized_after_key_canonicalization(self):
        result = redact({
            "can_id": "0x123",
            "CAN-ID": "0x456",
        }, "secret")

        self.assertEqual(result["can_id"], 0x123)
        self.assertEqual(result["CAN-ID"], 0x456)

    def test_invalid_can_id_is_cleared_without_aborting_redaction(self):
        result = redact({"can_id": "not-a-can-id", "vin": "V"}, "secret")
        self.assertIsNone(result["can_id"])
        self.assertTrue(result["vin"].startswith("p_"))

    def test_timestamp_alias_cannot_be_overwritten_by_precise_bucket(self):
        # The alias is intentionally before timestamp_bucket to exercise the
        # order-dependent overwrite that previously leaked exact timestamps.
        result = redact({
            "timeStamp": 1710000123,
            "timestamp_bucket": 1710000123,
        }, "secret")

        self.assertEqual(result["timestamp_bucket"], 1710000120)

    def test_malformed_timestamp_does_not_abort_redaction(self):
        # One bad record must not prevent the rest of a JSONL export from
        # being sanitized, and the original value must not be copied through.
        result = redact({"timestamp": "not-a-timestamp", "vin": "V"}, "s")

        self.assertIsNone(result["timestamp_bucket"])
        self.assertNotIn("timestamp", result)
        self.assertTrue(result["vin"].startswith("p_"))

    def test_non_finite_timestamp_is_not_serialized_as_a_precise_value(self):
        result = redact({"timestamp": "NaN"}, "s")

        self.assertIsNone(result["timestamp_bucket"])

    def test_malformed_jsonl_returns_controlled_error_with_line_number(self):
        # A single broken record must identify the repair location and return
        # a CLI error instead of exposing a traceback or silently dropping it.
        with TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.jsonl"
            output_path = Path(directory) / "output.jsonl"
            input_path.write_text('{"vin":"V"}\n{"vin":\n', encoding="utf-8")

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    str(input_path),
                    str(output_path),
                    "--secret",
                    "secret",
                ])

            self.assertEqual(result, 2)
            self.assertIn("invalid JSON on input line 2", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
if __name__=="__main__": unittest.main()
