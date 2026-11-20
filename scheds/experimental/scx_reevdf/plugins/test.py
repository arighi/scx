#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Composition integration test. Run as root in a disposable test VM."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def run(*args, ok=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if (result.returncode == 0) != ok:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def main():
    host, plugin = map(str, map(Path.resolve, map(Path, sys.argv[1:])))
    assert Path("/sys/kernel/sched_ext/state").read_text().strip() == "disabled"
    run(host, "--verify")
    run(host, "--plugin", plugin, "--verify")
    run(host, "--plugin", plugin, "--exit-dump-len", "65536", "--verify")
    error = run(host, "--plugin", plugin, "--plugin", plugin, "--verify", ok=False)
    assert "multiple plugins replace enqueue" in error, error

    # Exercise both paths under scheduling and process churn. Profiling
    # distinguishes the unused built-in callback from its replacement.
    for args in [[], ["--plugin", plugin]]:
        with tempfile.TemporaryFile(mode="w+") as output:
            process = subprocess.Popen(
                [host, *args, "--duration", "8", "--stats", "0.1", "-v"],
                stdout=output, stderr=output,
            )
            workers = []
            try:
                deadline = time.monotonic() + 30
                accounted = False
                while process.poll() is None and time.monotonic() < deadline:
                    if not workers and Path("/sys/kernel/sched_ext/state").read_text().strip() == "enabled":
                        # Pin competition so wakeups cannot escape to idle.
                        cpu = min(os.sched_getaffinity(0))
                        code = """
import os, sys, time
os.sched_setaffinity(0, {int(sys.argv[1])})
end = time.monotonic() + 15
while time.monotonic() < end:
    until = time.process_time() + 0.003
    while time.process_time() < until:
        pass
    if sys.argv[2] == 'sleeper':
        time.sleep(0.001)
"""
                        workers = [subprocess.Popen([sys.executable, "-c", code, str(cpu), kind])
                                   for kind in ["busy", "busy", "sleeper"]]
                    for _ in range(8):
                        run("/bin/true")
                    programs = json.loads(run("bpftool", "-j", "prog", "show"))
                    counts = [p.get("run_cnt", 0) for p in programs if p.get("name") == "scx_enqueue"]
                    inherited = [p.get("run_cnt", 0) for p in programs if p.get("name") == "scx_select_cid"]
                    # Enumeration is not atomic with loading or teardown.
                    # Require a complete active sample at least once; the
                    # last sample can legitimately contain fewer programs.
                    complete = not args or (len(counts) == 2 and min(counts) == 0)
                    active = process.poll() is None and Path("/sys/kernel/sched_ext/state").read_text().strip() == "enabled"
                    if active and complete and counts and max(counts) > 0 and inherited and max(inherited) > 0:
                        accounted = True
                    time.sleep(0.05)
                assert process.wait(timeout=10) == 0
                assert accounted, "no accounting for selected and inherited callbacks"
                output.seek(0)
                log = output.read()
                assert "errors=0 failures=0" in log, log[-12000:]
                assert "scheduler stopped" in log, log[-12000:]
                borrowed = sum(map(int, re.findall(r"plugin borrowing\.wakeups (\d+)", log)))
                assert (borrowed > 0) == bool(args), f"borrowed={borrowed}\n{log[-12000:]}"
            except BaseException:
                process.kill()
                process.wait()
                output.seek(0)
                print(output.read()[-12000:], file=sys.stderr)
                raise
            finally:
                for worker in workers:
                    worker.terminate()
                for worker in workers:
                    worker.wait(timeout=10)
        assert Path("/sys/kernel/sched_ext/state").read_text().strip() == "disabled"
    print(f"PASS: verifier, conflicts, callback selection, {borrowed} credited wakeups and arena teardown")


if __name__ == "__main__":
    main()
