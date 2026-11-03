"""No network or API needed; colors only in actual TTY."""
import importlib.util
import io
import os
import types
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

p = Path(__file__).resolve().parents[1] / 'pm.py'
spec = importlib.util.spec_from_file_location('pm_console_v4', p)
pm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pm)

class FakeTTY(io.StringIO):
    def isatty(self): return True

class Tests(unittest.TestCase):
    def test_constraints_are_per_task_not_global(self):
        self.assertEqual(pm.compose_task_description('Inspect lab', ''), 'Inspect lab')
        self.assertEqual(pm.compose_task_description('Inspect lab', 'Без брутфорса'),
                         'Inspect lab\nОграничения: Без брутфорса')
        with self.assertRaises(pm.OperatorError):
            pm.compose_task_description(' ', '')

    def test_tty_gets_ansi_but_captured_output_not(self):
        with patch.dict(os.environ, {'TERM': 'xterm-256color'}, clear=False):
            with redirect_stdout(io.StringIO()) as captured:
                self.assertNotIn('\x1b[', pm.tint('START'))
                pm.line(pm.tint('START'))
            self.assertNotIn('\x1b[', captured.getvalue())
            self.assertIn('\x1b[', pm.tint('START', stream=FakeTTY()))
            with patch.dict(os.environ, {'NO_COLOR': '1'}):
                self.assertNotIn('\x1b[', pm.tint('START', stream=FakeTTY()))

    def test_banner_and_menu_are_human_readable(self):
        prompts = ['0']
        with patch('builtins.input', side_effect=prompts), patch.object(pm, 'session_api_key', return_value='test'):
            with redirect_stdout(io.StringIO()) as output:
                pm.interactive()
        out = output.getvalue()
        self.assertIn('PENTEST MASTER', out)
        self.assertIn('ГЛАВНОЕ МЕНЮ', out)
        self.assertIn('НОВАЯ ЦЕЛЬ', out)
        self.assertNotIn('без брутфорса', out.lower())

    def test_progress_does_not_recursively_print_to_its_own_writer(self):
        out = io.StringIO()
        progress = pm.ConciseProgress(out)
        with redirect_stdout(progress):
            print('[JOB] #10: completed')
            print('[AGENT] RECON')
            print('[ROUND 1] observations=2+0 pending=0')
        self.assertIn('[JOB] #10', out.getvalue())
        self.assertIn('[АНАЛИЗ] RECON', out.getvalue())
        self.assertIn('observations=2', out.getvalue())

    def test_untrusted_output_is_sanitized(self):
        self.assertEqual(pm.safe_display('Server\x1b[31m\x07evil'), 'Server evil')

if __name__ == '__main__': unittest.main(verbosity=2)
