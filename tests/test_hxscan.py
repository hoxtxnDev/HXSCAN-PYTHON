import unittest
from hxscan import _parse_port_spec, _get_service_name, _SERVICE_MAP, ScanResult


class TestParsePortSpec(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(_parse_port_spec("80"), [80])

    def test_multiple_ports(self):
        self.assertEqual(_parse_port_spec("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(_parse_port_spec("8000-8003"), [8000, 8001, 8002, 8003])

    def test_mixed(self):
        self.assertEqual(_parse_port_spec("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_deduplicates(self):
        self.assertEqual(_parse_port_spec("80,80,80"), [80])

    def test_invalid_range_raises(self):
        with self.assertRaises(ValueError):
            _parse_port_spec("8000-7999")

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            _parse_port_spec("0")
        with self.assertRaises(ValueError):
            _parse_port_spec("70000")

    def test_empty_token_ignored(self):
        self.assertEqual(_parse_port_spec("22,,80"), [22, 80])


class TestServiceMap(unittest.TestCase):
    def test_known_ports(self):
        self.assertEqual(_get_service_name(22), "SSH")
        self.assertEqual(_get_service_name(80), "HTTP")
        self.assertEqual(_get_service_name(443), "HTTPS")
        self.assertEqual(_get_service_name(3306), "MySQL")
        self.assertEqual(_get_service_name(3389), "RDP")

    def test_unknown_port(self):
        self.assertEqual(_get_service_name(9999), "unknown")

    def test_all_ports_in_map_are_valid(self):
        for port in _SERVICE_MAP:
            self.assertGreaterEqual(port, 1)
            self.assertLessEqual(port, 65535)


class TestScanResult(unittest.TestCase):
    def test_open_port_gets_service(self):
        r = ScanResult(port=22, state="open")
        self.assertEqual(r.service, "SSH")

    def test_closed_port_unknown_service(self):
        r = ScanResult(port=9999, state="closed")
        self.assertEqual(r.service, "unknown")

    def test_open_unknown_port(self):
        r = ScanResult(port=9999, state="open")
        self.assertEqual(r.service, "unknown")

    def test_error_state(self):
        r = ScanResult(port=80, state="error", service="timeout")
        self.assertEqual(r.service, "timeout")


if __name__ == "__main__":
    unittest.main()
