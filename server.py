import asyncio
import json
import logging
import time
from aiocoap import Context, Message, resource, CHANGED, CONTENT, BAD_REQUEST, FORBIDDEN

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("secure-coap-cps")

STATE = {
    "soil_moisture": 24.5,
    "temperature": 29.2,
    "pump_on": False,
    "started_at": time.time(),
    "requests": 0,
    "rejected": 0,
    "last_sequence": {},
}
# Demo policy only. On a DTLS version, map roles to authenticated transport identities.
DEVICE_ROLES = {"sensor-01": "sensor", "controller-01": "controller"}

def payload(data):
    return json.dumps(data).encode("utf-8")

class Moisture(resource.Resource):
    async def render_get(self, request):
        STATE["requests"] += 1
        return Message(code=CONTENT, payload=payload({
            "device_id": "sensor-01", "soil_moisture": STATE["soil_moisture"],
            "unit": "percent", "timestamp": time.time(),
            "security_note": "plain CoAP milestone; not secure"
        }))

class Temperature(resource.Resource):
    async def render_get(self, request):
        STATE["requests"] += 1
        return Message(code=CONTENT, payload=payload({
            "device_id": "sensor-01", "temperature": STATE["temperature"],
            "unit": "C", "timestamp": time.time()
        }))

class DeviceStatus(resource.Resource):
    async def render_get(self, request):
        STATE["requests"] += 1
        return Message(code=CONTENT, payload=payload({
            "gateway": "online", "pump_on": STATE["pump_on"],
            "requests": STATE["requests"], "rejected_commands": STATE["rejected"],
            "uptime_seconds": round(time.time() - STATE["started_at"], 2)
        }))

class Pump(resource.Resource):
    async def render_get(self, request):
        STATE["requests"] += 1
        return Message(code=CONTENT, payload=payload({
            "pump_on": STATE["pump_on"], "mode": "simulated actuator"
        }))

    async def render_post(self, request):
        STATE["requests"] += 1
        try:
            data = json.loads(request.payload.decode("utf-8"))
            device_id = str(data["device_id"])
            sequence = int(data["sequence"])
            command = str(data["command"]).upper()
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            STATE["rejected"] += 1
            return Message(code=BAD_REQUEST, payload=b"Invalid JSON or missing fields")

        # WARNING: plain CoAP does not authenticate this JSON device_id.
        if DEVICE_ROLES.get(device_id) != "controller":
            STATE["rejected"] += 1
            return Message(code=FORBIDDEN, payload=b"Controller role required")

        previous = STATE["last_sequence"].get(device_id, -1)
        if sequence <= previous:
            STATE["rejected"] += 1
            return Message(code=FORBIDDEN, payload=b"Duplicate or stale application sequence")
        if command not in ("PUMP_ON", "PUMP_OFF"):
            STATE["rejected"] += 1
            return Message(code=BAD_REQUEST, payload=b"Unsupported command")

        # Production code must persist this and update atomically.
        STATE["last_sequence"][device_id] = sequence
        STATE["pump_on"] = command == "PUMP_ON"
        log.info("Accepted simulated command %s sequence=%d", command, sequence)
        return Message(code=CHANGED, payload=payload({
            "accepted": True, "pump_on": STATE["pump_on"], "sequence": sequence
        }))

async def main():
    site = resource.Site()
    site.add_resource(["sensor", "moisture"], Moisture())
    site.add_resource(["sensor", "temperature"], Temperature())
    site.add_resource(["device", "status"], DeviceStatus())
    site.add_resource(["actuator", "pump"], Pump())
    await Context.create_server_context(site, bind=("127.0.0.1", 5683))
    log.info("Plain CoAP demo listening at coap://127.0.0.1:5683")
    log.warning("Insecure local milestone. Do not expose to a network.")
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
