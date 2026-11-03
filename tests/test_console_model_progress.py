"""Offline: agent retry/error summary is visible and sanitized in terminal UI."""
import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pm_recovery_test', ROOT / 'pm.py')
pm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pm)


class ModelProgressTests(unittest.TestCase):
    def test_model_retry_is_visible(self):
        output = io.StringIO()
        progress = pm.ConciseProgress(output)
        progress.write('[MODEL] RECON: finish_reason=error; retry 1/1\n')
        self.assertIn('retry 1/1', output.getvalue())
        self.assertIn('MODEL', output.getvalue())

    def test_untrusted_ansi_is_stripped(self):
        output = io.StringIO()
        progress = pm.ConciseProgress(output)
        progress.write('[MODEL] rejected \x1b[31mBAD\x1b[0m\n')
        self.assertNotIn('\x1b[', output.getvalue())

if __name__ == '__main__':
    unittest.main(verbosity=2)
