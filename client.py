import argparse
import asyncio
import json
import time
from aiocoap import Context, Message, GET, POST

BASE = "coap://127.0.0.1:5683"

async def request(method, path, data=None):
    protocol = await Context.create_client_context()
    try:
        message = Message(code=method, uri=BASE + path)
        if data is not None:
            message.payload = json.dumps(data).encode("utf-8")
        start = time.perf_counter()
        response = await protocol.request(message).response
        elapsed_ms = (time.perf_counter() - start) * 1000
        print(f"Code: {response.code}")
        print(f"Latency: {elapsed_ms:.3f} ms")
        try:
            print(json.dumps(json.loads(response.payload.decode()), indent=2))
        except (ValueError, UnicodeDecodeError):
            print(response.payload.decode("utf-8", errors="replace"))
    finally:
        await protocol.shutdown()

def main():
    parser = argparse.ArgumentParser(description="Local CoAP demo client")
    sub = parser.add_subparsers(dest="action", required=True)
    getp = sub.add_parser("get")
    getp.add_argument("path", choices=[
        "/sensor/moisture", "/sensor/temperature", "/device/status", "/actuator/pump"
    ])
    onp = sub.add_parser("pump-on")
    onp.add_argument("--sequence", type=int, default=int(time.time()))
    offp = sub.add_parser("pump-off")
    offp.add_argument("--sequence", type=int, default=int(time.time()))
    args = parser.parse_args()
    if args.action == "get":
        asyncio.run(request(GET, args.path))
    else:
        command = "PUMP_ON" if args.action == "pump-on" else "PUMP_OFF"
        data = {"device_id": "controller-01", "sequence": args.sequence, "command": command}
        asyncio.run(request(POST, "/actuator/pump", data))

if __name__ == "__main__":
    main()
