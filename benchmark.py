"""Comprehensive Performance Benchmarking and Evaluation Suite.

Compares Plain CoAP (UDP 5683) vs Secure CoAP over DTLS 1.2 (UDP 5684).
Measures:
- Latency distribution (Mean, Median, P95, Min, Max)
- Throughput (req/s)
- Communication wire overhead (Bytes on wire vs payload)
- Handshake duration
- CPU utilization & memory consumption (RSS MB)

Saves repeatable empirical results to CSV, JSON, and publication-ready plots.
"""

import argparse
import asyncio
import csv
import json
import os
import statistics
import time
import psutil
import matplotlib.pyplot as plt
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
    """Measures Plain CoAP performance on port 5683."""
    print(f"\n[BENCHMARK] Running Plain CoAP ({num_requests} requests)...")
    uri = "coap://127.0.0.1:5683/sensor/moisture"
    protocol = await Context.create_client_context()
    latencies = []
    successes = 0
    wire_sent = 0
    wire_recv = 0
    
    proc = psutil.Process()
    cpu_before = proc.cpu_times()
    mem_before = proc.memory_info().rss / (1024 * 1024)
    start_all = time.perf_counter()
    
    try:
        for i in range(num_requests):
            t0 = time.perf_counter()
            try:
                msg = Message(code=GET, uri=uri)
                resp = await protocol.request(msg).response
                lat_ms = (time.perf_counter() - t0) * 1000.0
                latencies.append(lat_ms)
                if resp.code.is_successful():
                    successes += 1
                # Plain CoAP estimate: 4 bytes header + ~16 bytes options + payload
                wire_sent += 20
                wire_recv += 20 + len(resp.payload or b"")
            except Exception as e:
                lat_ms = (time.perf_counter() - t0) * 1000.0
                latencies.append(lat_ms)
    finally:
        await protocol.shutdown()

    duration = time.perf_counter() - start_all
    cpu_after = proc.cpu_times()
    cpu_sec = (cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system)
    mem_after = proc.memory_info().rss / (1024 * 1024)
    
    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered)-1, int(0.95 * (len(ordered)-1)))] if ordered else 0.0

    return {
        "mode": "plain_coap_udp",
        "requests": num_requests,
        "successes": successes,
        "duration_seconds": round(duration, 4),
        "throughput_rps": round(successes / duration, 2) if duration > 0 else 0.0,
        "mean_latency_ms": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "median_latency_ms": round(statistics.median(latencies), 3) if latencies else 0.0,
        "p95_latency_ms": round(p95, 3),
        "min_latency_ms": round(min(latencies), 3) if latencies else 0.0,
        "max_latency_ms": round(max(latencies), 3) if latencies else 0.0,
        "std_latency_ms": round(statistics.stdev(latencies), 3) if len(latencies) > 1 else 0.0,
        "mean_handshake_ms": 0.0,  # Plain CoAP has no handshake
        "avg_wire_sent_bytes": round(wire_sent / num_requests, 1) if num_requests else 0,
        "avg_wire_recv_bytes": round(wire_recv / num_requests, 1) if num_requests else 0,
        "cpu_seconds": round(cpu_sec, 6),
        "memory_mb": round(mem_after, 2),
        "cipher": "None (Plaintext)"
    }

def benchmark_dtls_coap(num_requests: int) -> dict:
    """Measures DTLS CoAP performance on port 5684."""
    print(f"\n[BENCHMARK] Running Secure DTLS 1.2 CoAP ({num_requests} requests)...")
    client = DTLSClient(cert_path=SENSOR_CRT, key_path=SENSOR_KEY, ca_path=CA_PATH, timeout=4.0)
    latencies = []
    handshakes = []
    successes = 0
    total_wire_sent = 0
    total_wire_recv = 0
    cipher_name = "ECDHE-RSA-AES256-GCM-SHA384"
    
    proc = psutil.Process()
    cpu_before = proc.cpu_times()
    start_all = time.perf_counter()
    
    for i in range(num_requests):
        msg = Message(code=GET, uri="coaps://127.0.0.1:5684/sensor/moisture")
        resp, stats = client.send_coap_request("127.0.0.1", 5684, msg)
        if resp is not None and resp.code.is_successful():
            successes += 1
            latencies.append(stats["total_time_ms"])
            handshakes.append(stats["handshake_time_ms"])
            total_wire_sent += stats["wire_bytes_sent"]
            total_wire_recv += stats["wire_bytes_received"]
            if stats.get("cipher"):
                cipher_name = stats["cipher"]
        else:
            latencies.append(stats.get("total_time_ms", 0.0))

    duration = time.perf_counter() - start_all
    cpu_after = proc.cpu_times()
    cpu_sec = (cpu_after.user + cpu_after.system) - (cpu_before.user + cpu_before.system)
    mem_after = proc.memory_info().rss / (1024 * 1024)

    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered)-1, int(0.95 * (len(ordered)-1)))] if ordered else 0.0

    return {
        "mode": "secure_coap_dtls",
        "requests": num_requests,
        "successes": successes,
        "duration_seconds": round(duration, 4),
        "throughput_rps": round(successes / duration, 2) if duration > 0 else 0.0,
        "mean_latency_ms": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "median_latency_ms": round(statistics.median(latencies), 3) if latencies else 0.0,
        "p95_latency_ms": round(p95, 3),
        "min_latency_ms": round(min(latencies), 3) if latencies else 0.0,
        "max_latency_ms": round(max(latencies), 3) if latencies else 0.0,
        "std_latency_ms": round(statistics.stdev(latencies), 3) if len(latencies) > 1 else 0.0,
        "mean_handshake_ms": round(statistics.mean(handshakes), 3) if handshakes else 0.0,
        "avg_wire_sent_bytes": round(total_wire_sent / successes, 1) if successes else 0,
        "avg_wire_recv_bytes": round(total_wire_recv / successes, 1) if successes else 0,
        "cpu_seconds": round(cpu_sec, 6),
        "memory_mb": round(mem_after, 2),
        "cipher": cipher_name
    }

def generate_comparison_plots(plain_res: dict, dtls_res: dict):
    """Generates comparative visualization charts for latency and resources."""
    modes = ["Plain CoAP (Insecure)", "Secure CoAP (DTLS 1.2)"]
    
    # 1. Latency Comparison Plot
    fig, ax = plt.subplots(figsize=(8, 5))
    x = range(len(modes))
    width = 0.25
    medians = [plain_res["median_latency_ms"], dtls_res["median_latency_ms"]]
    means = [plain_res["mean_latency_ms"], dtls_res["mean_latency_ms"]]
    p95s = [plain_res["p95_latency_ms"], dtls_res["p95_latency_ms"]]

    ax.bar([i - width for i in x], medians, width, label="Median Latency (ms)", color="#3498db")
    ax.bar([i for i in x], means, width, label="Mean Latency (ms)", color="#2ecc71")
    ax.bar([i + width for i in x], p95s, width, label="P95 Latency (ms)", color="#e74c3c")

    ax.set_ylabel("Latency (milliseconds)")
    ax.set_title("Latency Comparison: Plain CoAP vs DTLS CoAP")
    ax.set_xticks(x)
    ax.set_xticklabels(modes)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    lat_path = os.path.join(RESULTS_DIR, "latency_comparison.png")
    plt.savefig(lat_path, dpi=300)
    plt.close()

    # 2. Resource & Overhead Plot
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Throughput
    tputs = [plain_res["throughput_rps"], dtls_res["throughput_rps"]]
    ax1.bar(modes, tputs, color=["#34495e", "#9b59b6"], width=0.5)
    ax1.set_ylabel("Throughput (requests/sec)")
    ax1.set_title("Throughput Comparison")
    ax1.grid(axis="y", linestyle="--", alpha=0.7)

    # Overhead (Bytes sent/recv)
    wire_bytes = [
        plain_res["avg_wire_sent_bytes"] + plain_res["avg_wire_recv_bytes"],
        dtls_res["avg_wire_sent_bytes"] + dtls_res["avg_wire_recv_bytes"]
    ]
    ax2.bar(modes, wire_bytes, color=["#16a085", "#d35400"], width=0.5)
    ax2.set_ylabel("Average Round-trip Wire Bytes")
    ax2.set_title("Communication Protocol Overhead")
    ax2.grid(axis="y", linestyle="--", alpha=0.7)

    plt.tight_layout()
    res_path = os.path.join(RESULTS_DIR, "resource_comparison.png")
    plt.savefig(res_path, dpi=300)
    plt.close()
    print(f"Generated comparison plots:\n  {lat_path}\n  {res_path}")

def run_benchmark_suite(requests: int = 50):
    plain_stats = asyncio.run(benchmark_plain_coap(requests))
    dtls_stats = benchmark_dtls_coap(requests)

    csv_path = os.path.join(RESULTS_DIR, "benchmark_comparison.csv")
    fieldnames = list(plain_stats.keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(plain_stats)
        writer.writerow(dtls_stats)

    json_path = os.path.join(RESULTS_DIR, "benchmark_summary.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"plain": plain_stats, "dtls": dtls_stats}, f, indent=2)

    generate_comparison_plots(plain_stats, dtls_stats)

    print("\n" + "=" * 65)
    print("           BENCHMARK COMPARISON RESULTS")
    print("=" * 65)
    print(f"{'Metric':<28} | {'Plain CoAP':<16} | {'DTLS CoAP':<16}")
    print("-" * 65)
    print(f"{'Success Rate':<28} | {plain_stats['successes']}/{plain_stats['requests']:<14} | {dtls_stats['successes']}/{dtls_stats['requests']:<14}")
    print(f"{'Throughput (req/s)':<28} | {plain_stats['throughput_rps']:<16} | {dtls_stats['throughput_rps']:<16}")
    print(f"{'Median Latency (ms)':<28} | {plain_stats['median_latency_ms']:<16} | {dtls_stats['median_latency_ms']:<16}")
    print(f"{'Mean Latency (ms)':<28} | {plain_stats['mean_latency_ms']:<16} | {dtls_stats['mean_latency_ms']:<16}")
    print(f"{'P95 Latency (ms)':<28} | {plain_stats['p95_latency_ms']:<16} | {dtls_stats['p95_latency_ms']:<16}")
    print(f"{'DTLS Handshake (ms)':<28} | {'N/A (None)':<16} | {dtls_stats['mean_handshake_ms']:<16}")
    print(f"{'CPU Time (sec)':<28} | {plain_stats['cpu_seconds']:<16} | {dtls_stats['cpu_seconds']:<16}")
    print(f"{'Memory Usage (MB)':<28} | {plain_stats['memory_mb']:<16} | {dtls_stats['memory_mb']:<16}")
    print(f"{'Security Protection':<28} | {'None (Clear)':<16} | {'DTLS 1.2 AEAD':<16}")
    print("=" * 65)
    print(f"Results successfully saved to:\n  {csv_path}\n  {json_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure CoAP Performance Benchmark")
    parser.add_argument("--requests", type=int, default=50, help="Number of benchmark iterations")
    args = parser.parse_args()
    run_benchmark_suite(args.requests)
