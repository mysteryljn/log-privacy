import unittest
from redact import redact
class RedactTests(unittest.TestCase):
    def test_sensitive_fields(self):
        result=redact({"timestamp":121,"vin":"VIN","gps":{"lat":1},"user_id":"u"},"secret")
        self.assertTrue(result["vin"].startswith("p_")); self.assertNotIn("gps",result); self.assertEqual(result["timestamp_bucket"],120)
    def test_stable_pseudonym(self):
        self.assertEqual(redact({"vin":"V"},"s")["vin"],redact({"vin":"V"},"s")["vin"])
if __name__=="__main__": unittest.main()
