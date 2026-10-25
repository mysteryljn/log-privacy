import unittest
from redact import redact
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

    def test_can_id_is_normalized_after_key_canonicalization(self):
        result = redact({
            "can_id": "0x123",
            "CAN-ID": "0x456",
        }, "secret")

        self.assertEqual(result["can_id"], 0x123)
        self.assertEqual(result["CAN-ID"], 0x456)

    def test_timestamp_alias_cannot_be_overwritten_by_precise_bucket(self):
        # The alias is intentionally before timestamp_bucket to exercise the
        # order-dependent overwrite that previously leaked exact timestamps.
        result = redact({
            "timeStamp": 1710000123,
            "timestamp_bucket": 1710000123,
        }, "secret")

        self.assertEqual(result["timestamp_bucket"], 1710000120)
if __name__=="__main__": unittest.main()
