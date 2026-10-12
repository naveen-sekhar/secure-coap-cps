"""Performance Benchmark: Plain CoAP vs Secure DTLS CoAP.

Measures:
- Latency (Median, Mean, P95)
- Throughput (Requests per second)
- Handshake overhead
- CPU and Memory footprint
"""

import argparse
import asyncio
import csv
import os
import statistics
import time
import psutil
from aiocoap import Context, Message, GET
from crypto_utils import CERTS_DIR, ensure_credentials
from dtls_transport import DTLSClient

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

ensure_credentials()
CA_PATH = os.path.join(CERTS_DIR, "ca.crt")
SENSOR_CRT = os.path.join(CERTS_DIR, "sensor_01.crt")
SENSOR_KEY = os.path.join(CERTS_DIR, "sensor_01.key")

async def benchmark_plain_coap(num_requests: int) -> dict:
    """Measures insecure Plain CoAP baseline on port 5683."""
    print(f"\n[1/2] Benchmarking Plain CoAP (port 5683, {num_requests} requests)...")
    uri = "coap://127.0.0.1:5683/sensor/moisture"
    protocol = await Context.create_client_context()
    latencies = []
    successes = 0

    proc = psutil.Process()
    cpu_before = proc.cpu_times()
    start_all = time.perf_counter()

    try:
        for _ in range(num_requests):
            t0 = time.perf_counter()
            try:
                resp = await protocol.request(Message(code=GET, uri=uri)).response
                lat_ms = (time.perf_counter() - t0) * 1000.0
                latencies.append(lat_ms)
                if resp.code.is_successful():
                    successes += 1
            except Exception:
                latencies.append((time.perf_counter() - t0) * 1000.0)
    finally:
        await protocol.shutdown()

    duration = time.perf_counter() - start_all
    cpu_after = proc.cpu_times()
    cpu_sec = (cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system)
    mem_mb = proc.memory_info().rss / (1024 * 1024)

    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered) - 1, int(0.95 * (len(ordered) - 1)))] if ordered else 0.0

    return {
        "mode": "Plain CoAP (No DTLS)",
        "requests": num_requests,
        "successes": successes,
        "duration_sec": round(duration, 4),
        "throughput_rps": round(successes / duration, 2) if duration > 0 else 0.0,
        "median_latency_ms": round(statistics.median(latencies), 3) if latencies else 0.0,
        "mean_latency_ms": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "p95_latency_ms": round(p95, 3),
        "handshake_ms": 0.0,
        "cpu_seconds": round(cpu_sec, 4),
        "memory_mb": round(mem_mb, 1),
        "encryption": "None (Cleartext UDP)"
    }

def benchmark_dtls_coap(num_requests: int) -> dict:
    """Measures Secure CoAP over DTLS 1.2 on port 5684."""
    print(f"[2/2] Benchmarking Secure DTLS CoAP (port 5684, {num_requests} requests)...")
    client = DTLSClient(cert_path=SENSOR_CRT, key_path=SENSOR_KEY, ca_path=CA_PATH, timeout=4.0)
    latencies = []
    handshakes = []
    successes = 0

    proc = psutil.Process()
    cpu_before = proc.cpu_times()
    start_all = time.perf_counter()

    for _ in range(num_requests):
        msg = Message(code=GET, uri="coaps://127.0.0.1:5684/sensor/moisture")
        resp, stats = client.send_coap_request("127.0.0.1", 5684, msg)
        if resp is not None and resp.code.is_successful():
            successes += 1
            latencies.append(stats["total_time_ms"])
            handshakes.append(stats["handshake_time_ms"])
        else:
            latencies.append(stats.get("total_time_ms", 0.0))

    duration = time.perf_counter() - start_all
    cpu_after = proc.cpu_times()
    cpu_sec = (cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system)
    mem_mb = proc.memory_info().rss / (1024 * 1024)

    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered) - 1, int(0.95 * (len(ordered) - 1)))] if ordered else 0.0

    return {
        "mode": "Secure CoAP (DTLS 1.2)",
        "requests": num_requests,
        "successes": successes,
        "duration_sec": round(duration, 4),
        "throughput_rps": round(successes / duration, 2) if duration > 0 else 0.0,
        "median_latency_ms": round(statistics.median(latencies), 3) if latencies else 0.0,
        "mean_latency_ms": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "p95_latency_ms": round(p95, 3),
        "handshake_ms": round(statistics.mean(handshakes), 3) if handshakes else 0.0,
        "cpu_seconds": round(cpu_sec, 4),
        "memory_mb": round(mem_mb, 1),
        "encryption": "ECDHE-RSA-AES256-GCM-SHA384"
    }

def print_table(plain: dict, dtls: dict):
    print("\n" + "=" * 65)
    print("       PERFORMANCE COMPARISON: PLAIN COAP VS SECURE DTLS")
    print("=" * 65)
    print(f"{'Metric':<25} | {'Plain CoAP (5683)':<17} | {'DTLS CoAP (5684)':<17}")
    print("-" * 65)
    print(f"{'Success Rate':<25} | {plain['successes']}/{plain['requests']:<15} | {dtls['successes']}/{dtls['requests']:<15}")
    print(f"{'Throughput (req/s)':<25} | {plain['throughput_rps']:<17} | {dtls['throughput_rps']:<17}")
    print(f"{'Median Latency (ms)':<25} | {plain['median_latency_ms']:<17} | {dtls['median_latency_ms']:<17}")
    print(f"{'Mean Latency (ms)':<25} | {plain['mean_latency_ms']:<17} | {dtls['mean_latency_ms']:<17}")
    print(f"{'P95 Latency (ms)':<25} | {plain['p95_latency_ms']:<17} | {dtls['p95_latency_ms']:<17}")
    print(f"{'DTLS Handshake (ms)':<25} | {'N/A (No Security)':<17} | {dtls['handshake_ms']:<17}")
    print(f"{'CPU Time (sec)':<25} | {plain['cpu_seconds']:<17} | {dtls['cpu_seconds']:<17}")
    print(f"{'Memory Usage (MB)':<25} | {plain['memory_mb']:<17} | {dtls['memory_mb']:<17}")
    print(f"{'Security Protection':<25} | {'None (Insecure)':<17} | {'Mutual TLS (AEAD)':<17}")
    print("=" * 65)

def main():
    parser = argparse.ArgumentParser(description="Benchmark Plain vs DTLS CoAP")
    parser.add_argument("--requests", type=int, default=30, help="Number of benchmark requests")
    args = parser.parse_args()

    plain_res = asyncio.run(benchmark_plain_coap(args.requests))
    dtls_res = benchmark_dtls_coap(args.requests)

    print_table(plain_res, dtls_res)

    csv_path = os.path.join(RESULTS_DIR, "benchmark_comparison.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(plain_res.keys()))
        writer.writeheader()
        writer.writerow(plain_res)
        writer.writerow(dtls_res)

    print(f"\n[OK] Results saved to:\n  {csv_path}\n")

if __name__ == "__main__":
    main()
