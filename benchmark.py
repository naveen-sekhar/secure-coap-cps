import argparse
import asyncio
import csv
import os
import statistics
import time
import psutil
from aiocoap import Context, Message, GET

URI = "coap://127.0.0.1:5683/sensor/moisture"

async def run(requests, output):
    protocol = await Context.create_client_context()
    latencies, successes = [], 0
    process = psutil.Process()
    cpu_before = process.cpu_times()
    mem_mb = process.memory_info().rss / (1024 * 1024)
    start_all = time.perf_counter()
    try:
        for _ in range(requests):
            started = time.perf_counter()
            try:
                response = await protocol.request(Message(code=GET, uri=URI)).response
                latencies.append((time.perf_counter() - started) * 1000)
                if response.code.is_successful():
                    successes += 1
            except Exception:
                latencies.append((time.perf_counter() - started) * 1000)
    finally:
        await protocol.shutdown()
    duration = time.perf_counter() - start_all
    cpu_after = process.cpu_times()
    cpu_seconds = (cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system)
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered)-1, int(0.95 * (len(ordered)-1)))] if ordered else 0
    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "mode", "requests", "successes", "duration_seconds", "throughput_rps",
            "mean_latency_ms", "median_latency_ms", "p95_latency_ms",
            "process_cpu_seconds", "process_memory_mb"
        ])
        writer.writeheader()
        writer.writerow({
            "mode": "plain_coap_loopback", "requests": requests, "successes": successes,
            "duration_seconds": round(duration, 6),
            "throughput_rps": round(successes / duration, 3) if duration else 0,
            "mean_latency_ms": round(statistics.mean(latencies), 3) if latencies else 0,
            "median_latency_ms": round(statistics.median(latencies), 3) if latencies else 0,
            "p95_latency_ms": round(p95, 3),
            "process_cpu_seconds": round(cpu_seconds, 6),
            "process_memory_mb": round(mem_mb, 3)
        })
    print(f"Completed {successes}/{requests}; results: {output}")
    if duration:
        print(f"Throughput: {successes/duration:.2f} requests/s")
    if latencies:
        print(f"Median latency: {statistics.median(latencies):.3f} ms")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--output", default="results/plain_coap_baseline.csv")
    args = parser.parse_args()
    if args.requests < 1:
        parser.error("--requests must be >= 1")
    asyncio.run(run(args.requests, args.output))

if __name__ == "__main__":
    main()
