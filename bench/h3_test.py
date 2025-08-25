#!/usr/bin/env python3
import argparse
import asyncio
import os
import sys
import time
from collections import Counter
from statistics import mean


def build_curl_cmd(curl_path: str, url: str, http3_only: bool, insecure: bool, raw_i: bool):
    args = [curl_path]
    if http3_only:
        args.append("--http3-only")
    else:
        args.append("--http3")
    if insecure:
        args.append("-k")

    if raw_i:
        # Original-style output: headers+body to stdout; we will measure wall-clock.
        args.append("-i")
        args.append(url)
    else:
        # Efficient: quiet, no body, print code and timing for easy parsing.
        # Format: \"<code> <time_total>\\n\"
        args += ["-sS", "-o", os.devnull, "-w",
                 "%{http_code} %{time_total}\\n", url]
    return args


async def run_one(idx: int, sem: asyncio.Semaphore, curl_cmd: list[str], timeout: float, raw_i: bool):
    async with sem:
        start = time.perf_counter()
        try:
            if raw_i:
                proc = await asyncio.create_subprocess_exec(
                    *curl_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    outs, errs = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                    elapsed = time.perf_counter() - start
                    status_code = None
                    raw_proto = None
                    if outs:
                        first_line = outs.splitlines()[0].decode(
                            errors="ignore").strip()
                        parts = first_line.split()
                        if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
                            raw_proto = parts[0]
                            status_code = int(parts[1])
                    return (idx, status_code, elapsed, raw_proto)
                finally:
                    if proc.returncode is None:
                        proc.kill()
                        await proc.wait()
            else:
                # Efficient mode: status and time printed on stdout as: \"<code> <time_total>\\n\"
                proc = await asyncio.create_subprocess_exec(
                    *curl_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                outs, errs = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                if not outs:
                    return (idx, None, None, None)
                try:
                    line = outs.decode().strip().splitlines()[-1].strip()
                    code_str, time_str = line.split()
                    code = int(code_str)
                    elapsed = float(time_str)
                except Exception:
                    elapsed = time.perf_counter() - start
                    code = None
                return (idx, code, elapsed, "HTTP/3? (curl -w mode)")
        except asyncio.TimeoutError:
            return (idx, None, None, None)
        except FileNotFoundError:
            print(
                f"ERROR: curl binary not found at path: {curl_cmd[0]}", file=sys.stderr)
            return (idx, None, None, None)
        except Exception:
            return (idx, None, None, None)


async def main_async(args):
    total = args.requests
    sem = asyncio.Semaphore(args.concurrency)
    cmd = build_curl_cmd(
        args.curl_path, args.url, args.http3_only, args.insecure, args.raw_i
    )
    tasks = [run_one(i, sem, cmd, args.timeout, args.raw_i)
             for i in range(total)]
    results = []
    print(
        f"Starting {total} requests with concurrency={args.concurrency} using: {' '.join(cmd)}")
    started = time.perf_counter()
    CHUNK = 1000
    for i in range(0, total, CHUNK):
        chunk = tasks[i:i+CHUNK]
        results.extend(await asyncio.gather(*chunk))
        done = min(i+CHUNK, total)
        print(f"Progress: {done}/{total}")
    elapsed_total = time.perf_counter() - started

    latencies = [r[2] for r in results if r[2] is not None]
    codes = [r[1] for r in results if r[1] is not None]
    from collections import Counter
    code_counts = Counter(codes)
    ok_count = code_counts.get(200, 0)

    min_rt = min(latencies) if latencies else None
    avg_rt = mean(latencies) if latencies else None
    max_rt = max(latencies) if latencies else None

    csv_path = args.output
    try:
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("idx,status,elapsed_seconds\n")
            for idx, status, elapsed, _proto in results:
                s = "" if status is None else str(status)
                t = "" if elapsed is None else f"{elapsed:.6f}"
                f.write(f"{idx},{s},{t}\n")
        print(f"Wrote per-request results to: {csv_path}")
    except Exception as e:
        print(f"WARNING: could not write CSV: {e}", file=sys.stderr)

    print("\n=== Summary ===")
    print(f"Total requests: {total}")
    print(f"Successful 200 OK: {ok_count}")
    print(f"Non-200: {total - ok_count}")
    print("Status code breakdown:")
    for c in sorted(code_counts.keys()):
        print(f"  {c}: {code_counts[c]}")
    if min_rt is not None:
        print(f"Min latency: {min_rt*1000:.2f} ms")
        print(f"Avg latency: {avg_rt*1000:.2f} ms")
        print(f"Max latency: {max_rt*1000:.2f} ms")
    else:
        print("No latency data collected.")
    print(f"Wall-clock for whole run: {elapsed_total:.2f} s")

    return 0 if ok_count == total else 1


def parse_args():
    p = argparse.ArgumentParser(
        description="High-concurrency HTTP/3 curl load test")
    p.add_argument("--url", default="https://localhost:8080",
                   help="Target URL")
    p.add_argument("--curl-path", default="./curl",
                   help="Path to curl binary (must support --http3)")
    p.add_argument("--requests", type=int, default=10000,
                   help="Total number of requests to send")
    p.add_argument("--concurrency", type=int, default=10000,
                   help="Concurrent requests (CCU)")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Per-request timeout in seconds")
    p.add_argument(
        "--output", default="h3_results.csv", help="CSV output file for per-request data")
    p.add_argument(
        "--http3-only", action="store_true", help="Use --http3-only to forbid TCP fallback")
    p.add_argument(
        "--insecure", action="store_true", default=True, help="Pass -k to curl")
    p.add_argument("--raw-i", action="store_true",
                   help="Use raw '-i' mode exactly like the original command (slower; measures wall time)")
    return p.parse_args()


def main():
    args = parse_args()
    try:
        rc = asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        rc = 2
    sys.exit(rc)


if __name__ == "__main__":
    main()
