"""Security logic: Authentication binding, Role-Based Access Control (RBAC),
application-level replay protection with atomic persistence, and security event audit logging.
"""

import json
import logging
import os
import tempfile
import time
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("security")

# State & Log directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(BASE_DIR, "state")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
REPLAY_CACHE_FILE = os.path.join(STATE_DIR, "replay_cache.json")
SECURITY_EVENTS_FILE = os.path.join(LOGS_DIR, "security_events.jsonl")

os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Authenticated identity -> Role mapping
DEVICE_ROLES = {
    "sensor-01": "sensor",
    "sensor-02": "sensor",
    "controller-01": "controller",
    "coap-gateway": "gateway",
    "rogue-attacker": "attacker"
}

# Role permissions matrix
ROLE_PERMISSIONS = {
    "sensor": {"read_sensor", "submit_reading", "device_status"},
    "controller": {"read_sensor", "control_pump", "device_status"},
    "gateway": {"read_sensor", "submit_reading", "control_pump", "device_status", "admin"},
    "attacker": set()
}

# In-memory recent events ring buffer
MAX_EVENT_HISTORY = 100
_EVENT_HISTORY: List[dict] = []

def log_security_event(event_type: str, device_id: str, action: str, details: str, success: bool):
    """Logs a security audit event both in-memory and persistently to disk."""
    entry = {
        "timestamp": time.time(),
        "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "event_type": event_type,
        "device_id": device_id,
        "action": action,
        "details": details,
        "success": success
    }
    _EVENT_HISTORY.append(entry)
    if len(_EVENT_HISTORY) > MAX_EVENT_HISTORY:
        _EVENT_HISTORY.pop(0)
        
    try:
        with open(SECURITY_EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        log.error("Failed to write security event: %s", e)

def get_recent_security_events(limit: int = 50) -> List[dict]:
    """Returns recent security events from memory or disk."""
    if _EVENT_HISTORY:
        return list(reversed(_EVENT_HISTORY[-limit:]))
    if os.path.exists(SECURITY_EVENTS_FILE):
        try:
            with open(SECURITY_EVENTS_FILE, "r", encoding="utf-8") as f:
                lines = [json.loads(line.strip()) for line in f if line.strip()]
                return list(reversed(lines[-limit:]))
        except Exception:
            return []
    return []

def get_security_metrics() -> dict:
    """Calculates summary counts of security events."""
    events = get_recent_security_events(200)
    return {
        "total_events": len(events),
        "auth_failures": sum(1 for e in events if e.get("event_type") == "AUTH_FAIL"),
        "replay_blocked": sum(1 for e in events if e.get("event_type") == "REPLAY_BLOCKED"),
        "rbac_denied": sum(1 for e in events if e.get("event_type") == "RBAC_DENIED"),
        "commands_executed": sum(1 for e in events if e.get("event_type") == "COMMAND_ACCEPTED"),
    }

def authorized(device_id: str, action: str) -> bool:
    """Enforces Role-Based Access Control (RBAC)."""
    role = DEVICE_ROLES.get(device_id)
    if not role:
        log_security_event("RBAC_DENIED", device_id, action, "Unknown device identity", False)
        return False
        
    allowed_actions = ROLE_PERMISSIONS.get(role, set())
    is_allowed = action in allowed_actions
    if is_allowed:
        log_security_event("RBAC_PERMITTED", device_id, action, f"Role '{role}' authorized", True)
    else:
        log_security_event("RBAC_DENIED", device_id, action, f"Role '{role}' lacks permission for '{action}'", False)
    return is_allowed

def load_replay_state() -> Dict[str, int]:
    """Loads persistent sequence tracking state from disk."""
    if os.path.exists(REPLAY_CACHE_FILE):
        try:
            with open(REPLAY_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log.warning("Failed to load replay state, initializing empty: %s", e)
    return {}

def save_replay_state(state: Dict[str, int]):
    """Atomically persists sequence tracking state to disk."""
    try:
        temp_file = REPLAY_CACHE_FILE + ".tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(temp_file, REPLAY_CACHE_FILE)
    except Exception as e:
        log.error("Failed to save replay state: %s", e)

def accept_sequence(device_id: str, sequence: int, last_seen: Optional[Dict[str, int]] = None) -> bool:
    """Accept strictly monotonic sequence numbers; rejects duplicates, stale numbers, or bad types.
    Updates in-memory dictionary and persists atomically.
    """
    if last_seen is None:
        last_seen = load_replay_state()
        
    if device_id not in DEVICE_ROLES:
        log_security_event("REPLAY_BLOCKED", device_id, "sequence_check", "Unrecognized device identity", False)
        return False
        
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        log_security_event("REPLAY_BLOCKED", device_id, "sequence_check", f"Invalid sequence data type: {type(sequence)}", False)
        return False
        
    prev = last_seen.get(device_id, -1)
    if sequence <= prev:
        log_security_event("REPLAY_BLOCKED", device_id, "sequence_check", f"Duplicate/stale sequence {sequence} <= last {prev}", False)
        return False
        
    last_seen[device_id] = sequence
    save_replay_state(last_seen)
    return True
