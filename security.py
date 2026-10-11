"""Unit-testable app security logic. These checks do not replace DTLS."""

DEVICE_ROLES = {"sensor-01": "sensor", "controller-01": "controller"}

def authorized(device_id, action):
    role = DEVICE_ROLES.get(device_id)
    if action == "submit_reading":
        return role == "sensor"
    if action == "control_pump":
        return role == "controller"
    return False

def accept_sequence(device_id, sequence, last_seen):
    """Accept increasing sequence numbers; caller must authenticate the peer first."""
    if device_id not in DEVICE_ROLES:
        return False
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        return False
    if sequence <= last_seen.get(device_id, -1):
        return False
    last_seen[device_id] = sequence
    return True
