import os
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Secure CoAP CPS Monitor", layout="wide")
st.title("Secure CoAP CPS Monitor")
st.warning("Academic prototype: plain CoAP baseline only until DTLS is configured and verified.")

path = "results/plain_coap_baseline.csv"
if os.path.exists(path):
    df = pd.read_csv(path)
    row = df.iloc[-1]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Successful requests", f"{int(row['successes'])}/{int(row['requests'])}")
    c2.metric("Throughput", f"{row['throughput_rps']:.2f} req/s")
    c3.metric("Median latency", f"{row['median_latency_ms']:.3f} ms")
    c4.metric("Process memory", f"{row['process_memory_mb']:.1f} MB")
    st.subheader("Benchmark data")
    st.dataframe(df, use_container_width=True)
    st.bar_chart(df.set_index("mode")[["mean_latency_ms", "median_latency_ms", "p95_latency_ms"]])
else:
    st.info("No benchmark results yet. Start server.py and run: python benchmark.py --requests 100")

st.subheader("Planned security checks")
st.markdown("""
- DTLS peer authentication (not yet configured in this first milestone)
- Application authorization: sensor versus controller roles
- Application replay protection: reject duplicate/stale command sequence values
- Resource metrics: latency, throughput, process CPU time, process memory
- Packet inspection: compare plain CoAP with verified DTLS traffic in Wireshark
""")
