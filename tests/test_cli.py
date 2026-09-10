import unittest

from torproxy.cli.torproxy_ import BandwidthTracker, ProgressReporter, render_dashboard


class TestProgressReporter(unittest.TestCase):
    def test_tracks_latest_message(self):
        progress = ProgressReporter("starting")
        progress("running")
        self.assertEqual(progress.message, "running")


class TestBandwidthTracker(unittest.TestCase):
    def test_keeps_initial_labels_until_first_sample(self):
        tracker = BandwidthTracker()
        self.assertEqual(tracker.labels, ("0 Kbps", "0 Kbps"))

    def test_calculates_rates_after_interval(self):
        tracker = BandwidthTracker()
        tracker.update(0.0, 0, 0)
        up, down = tracker.update(1.0, 1000, 2000)
        self.assertEqual(up, "8 Kbps")
        self.assertEqual(down, "16 Kbps")


class TestDashboard(unittest.TestCase):
    def test_renders_stopped_state(self):
        rendered = render_dashboard(
            None,
            0,
            0,
            0,
            16 * 1024**3,
            8 * 1024**3,
            64 * 1024**2,
            15.0,
            "1 Mbps",
            "2 Mbps",
            "",
            120,
            30,
        )
        self.assertIn("TorProxy", rendered)
        self.assertIn("Proxy not running", rendered)


if __name__ == "__main__":
    unittest.main()
