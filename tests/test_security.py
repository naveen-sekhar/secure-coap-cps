import unittest
from security import authorized, accept_sequence

class SecurityLogicTests(unittest.TestCase):
    def test_sensor_can_submit_reading(self):
        self.assertTrue(authorized("sensor-01", "submit_reading"))
    def test_sensor_cannot_control_pump(self):
        self.assertFalse(authorized("sensor-01", "control_pump"))
    def test_controller_can_control_pump(self):
        self.assertTrue(authorized("controller-01", "control_pump"))
    def test_unknown_device_denied(self):
        self.assertFalse(authorized("unknown", "control_pump"))
    def test_increasing_sequence_accepted(self):
        state = {}
        self.assertTrue(accept_sequence("controller-01", 1, state))
        self.assertTrue(accept_sequence("controller-01", 2, state))
    def test_duplicate_and_stale_rejected(self):
        state = {"controller-01": 5}
        self.assertFalse(accept_sequence("controller-01", 5, state))
        self.assertFalse(accept_sequence("controller-01", 4, state))
    def test_unknown_sequence_rejected(self):
        self.assertFalse(accept_sequence("unknown", 1, {}))

if __name__ == "__main__":
    unittest.main()
