"""The one bounded subprocess runner.

``subprocess.run(..., timeout=T)`` is not a bounded call on Windows. Two
mechanisms break it, and both were measured on real Windows CI in the
provenance project rather than argued from the source:

* On expiry CPython kills only the DIRECT child and then calls ``communicate()``
  with no timeout, which blocks until the stdout pipe reaches EOF. A
  grandchild that inherited the write end keeps the caller blocked —
  indefinitely if it never exits.
* Windows' ``communicate()`` implements the timeout with reader threads; when
  a grandchild holds the pipe the call outlives its own bound.

``ssh-keygen`` can spawn such children through its agent integration, so a
hung verification call must not exceed the tool's declared bound.

:func:`run` therefore does not delegate its bound to ``communicate``. It
drains the pipes on a daemon thread and enforces the deadline itself with a
bounded thread join, which is honoured on every platform. On expiry it kills
the whole process tree and raises :class:`subprocess.TimeoutExpired`; callers
map that to exit 2 ("could not decide"), never exit 1 ("blocked"), so a hung
tool cannot be misread as a gate decision.

Encoding is pinned to UTF-8 with ``errors="replace"`` so non-ASCII output does
not depend on the host code page. Stdlib only; ``shell=False``, always.
"""

import os
import subprocess
import threading

GRACE = 1.0      # seconds to let the reader finish after a tree kill
REAP = 5.0       # seconds to wait for the direct child after a tree kill


def _kill_tree(process):
    """Kill the child AND its descendants. Best-effort: a failure here must
    never mask the timeout we are about to report."""
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True, shell=False, timeout=10,
                encoding="utf-8", errors="replace",
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def run(argv, *, timeout=None, cwd=None, env=None, text=True, stdin=None):
    """Run ``argv`` (an argv array — never a shell) under a real wall bound.

    Returns a ``subprocess.CompletedProcess``-shaped result with
    ``.returncode``, ``.stdout`` and ``.stderr``. On expiry the whole process
    tree is killed and :class:`subprocess.TimeoutExpired` is raised.
    """
    process = subprocess.Popen(
        argv,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
        shell=False,
        encoding="utf-8" if text else None,
        errors="replace" if text else None,
    )
    box = {}
    moved = threading.Event()

    def _drain():
        try:
            box["out"], box["err"] = process.communicate()
        except BaseException as exc:            # pragma: no cover - defensive
            box["exc"] = exc
        finally:
            moved.set()

    reader = threading.Thread(target=_drain, name="nullaosta-proc-reader",
                              daemon=True)
    reader.start()
    moved.wait(timeout)                         # OUR bound, honoured everywhere

    if not moved.is_set():
        # The deadline passed with the drain unfinished. Distinguish the two
        # cases BEFORE killing, because the kill makes them look alike:
        child_still_running = process.poll() is None
        _kill_tree(process)
        try:
            process.wait(timeout=REAP)
        except subprocess.TimeoutExpired:
            pass
        if child_still_running or not moved.wait(GRACE):
            raise subprocess.TimeoutExpired(argv, timeout or 0)
        # The child had ALREADY finished and only a stray descendant held the
        # pipe: the tree kill released it, so report the real result instead
        # of a false timeout.
        if "exc" in box:
            raise subprocess.TimeoutExpired(argv, timeout or 0)

    if "exc" in box:
        raise box["exc"]
    return subprocess.CompletedProcess(process.args, process.returncode,
                                       box.get("out"), box.get("err"))
