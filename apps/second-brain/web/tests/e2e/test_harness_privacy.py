from __future__ import annotations

import os
import runpy
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

HARNESS = runpy.run_path(str(Path(__file__).with_name("real-persistence-harness.py")))


class HarnessPrivacyTest(unittest.TestCase):
    def test_cleanup_kills_stalled_process_group_and_releases_port_within_budget(self) -> None:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        program = """
import signal
import socket
import time
import sys
listener=socket.socket()
listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
listener.bind(('127.0.0.1',int(sys.argv[1])))
listener.listen()
signal.signal(signal.SIGTERM,lambda *_: None)
print('ready',flush=True)
time.sleep(60)
"""
        child = HARNESS["spawn"](
            "stalled-cleanup-child",
            [sys.executable, "-c", program, str(port)],
            Path.cwd(),
            dict(os.environ),
        )
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                    break
            except OSError:
                time.sleep(0.01)
        else:
            self.fail("stalled cleanup child did not open its test port")

        started = time.monotonic()
        children = HARNESS["begin_child_cleanup"]()
        errors = HARNESS["cleanup_children_and_threads"](
            children,
            [],
            deadline=started + 2,
        )

        self.assertEqual(errors, [])
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsNotNone(child.process.poll())
        with socket.socket() as rebound:
            rebound.bind(("127.0.0.1", port))

    def test_recovery_status_is_bounded_for_pending_success_and_error(self) -> None:
        status_type = HARNESS["RecoveryProofStatus"]
        response = HARNESS["status_http_response"]
        status = status_type()

        self.assertEqual(response(status.snapshot()), (202, {"state": "pending"}))
        status.succeed()
        self.assertEqual(response(status.snapshot()), (200, {"state": "success"}))

        failed = status_type()
        failed.fail("recovery_failed")
        self.assertEqual(
            response(failed.snapshot()),
            (503, {"state": "error", "code": "recovery_failed"}),
        )

    def test_recovery_status_is_published_only_after_worker_completion(self) -> None:
        status_type = HARNESS["RecoveryProofStatus"]
        publish = HARNESS["publish_recovery_status"]
        release = threading.Event()
        recovery = threading.Thread(target=release.wait)
        recovery.start()
        status = status_type()
        publisher = threading.Thread(
            target=publish,
            args=(recovery, [], status),
            kwargs={"timeout": 1},
        )
        publisher.start()

        self.assertEqual(status.snapshot(), {"state": "pending"})
        release.set()
        publisher.join(timeout=1)

        self.assertFalse(recovery.is_alive())
        self.assertFalse(publisher.is_alive())
        self.assertEqual(status.snapshot(), {"state": "success"})

        failed_recovery = threading.Thread(target=lambda: None)
        failed_recovery.start()
        failed_status = status_type()
        publish(failed_recovery, ["private detail must not escape"], failed_status, timeout=1)
        self.assertEqual(
            failed_status.snapshot(),
            {"state": "error", "code": "recovery_failed"},
        )

        timed_release = threading.Event()
        timed_recovery = threading.Thread(target=timed_release.wait)
        timed_recovery.start()
        timed_status = status_type()
        publish(timed_recovery, [], timed_status, timeout=0.01)
        self.assertEqual(
            timed_status.snapshot(),
            {"state": "error", "code": "recovery_timeout"},
        )
        timed_release.set()
        timed_recovery.join(timeout=1)

    def test_private_marker_is_detected_across_read_boundaries(self) -> None:
        marker = HARNESS["SEEDED_PRIVATE_TEXT"]
        scan = HARNESS["scan_private_marker"]

        tail, found = scan(b"", b"prefix " + marker[:11])
        self.assertFalse(found)
        _, found = scan(tail, marker[11:] + b" suffix")

        self.assertTrue(found)

    def test_unfinished_recovery_thread_cannot_be_accepted(self) -> None:
        release = threading.Event()
        recovery = threading.Thread(target=release.wait, daemon=True)
        recovery.start()

        with self.assertRaisesRegex(RuntimeError, "did not complete"):
            HARNESS["require_recovery_completion"](recovery, threading.Event(), [], timeout=0.01)

        release.set()
        recovery.join(timeout=1)

    def test_recovery_thread_error_is_propagated(self) -> None:
        complete = threading.Event()
        errors = ["RuntimeError: recovery failed"]
        recovery = threading.Thread(target=complete.set, daemon=True)
        recovery.start()

        with self.assertRaisesRegex(RuntimeError, "recovery failed"):
            HARNESS["require_recovery_completion"](recovery, complete, errors, timeout=1)

    def test_spawn_is_rejected_after_cleanup_begins(self) -> None:
        HARNESS["begin_child_cleanup"]()

        with self.assertRaisesRegex(RuntimeError, "cleanup has begun"):
            HARNESS["spawn"](
                "forbidden",
                ["this-command-must-not-run"],
                Path.cwd(),
                {},
            )


if __name__ == "__main__":
    unittest.main()
