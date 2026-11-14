"""Inventory and process isolation checks without importing test subjects."""
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

path=Path(__file__).with_name('run_offline.py')
spec=importlib.util.spec_from_file_location('pm_offline_runner',path)
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def test_every_test_file_has_one_explicit_safety_category(self):
        runner.validate_inventory()

    def test_manual_tests_cannot_be_dispatched(self):
        for name in runner.MANUAL:
            with self.assertRaises(ValueError):runner.command(name)

    def test_script_and_unittest_suites_are_executed_in_fresh_processes(self):
        with patch.object(runner.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'OK')) as execute:
            runner.run_suite('test_auto_scheduler');runner.run_suite('test_evidence_pipeline')
        self.assertEqual(execute.call_count,2)
        for call in execute.call_args_list:
            self.assertEqual(call.args[0][0],sys.executable)
            self.assertEqual(call.kwargs['env']['PYTHONPATH'],str(runner.ROOT))
            self.assertEqual(call.kwargs['cwd'],runner.ROOT)
        self.assertIn('-m',execute.call_args_list[0].args[0])
        self.assertNotIn('-m',execute.call_args_list[1].args[0])

    def test_failures_skips_and_empty_suites_are_not_reported_as_success(self):
        for result in (subprocess.CompletedProcess([],1,'Ran 1 test in 0s\nFAILED (failures=1)'),
                       subprocess.CompletedProcess([],0,'Ran 1 test in 0s\nOK (skipped=1)'),
                       subprocess.CompletedProcess([],0,'Ran 0 tests in 0s\nOK')):
            with self.subTest(output=result.stdout),patch.object(runner,'run_suite',return_value=result),redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(['--only','test_auto_scheduler']),1)

    def test_empty_legacy_script_cannot_pass(self):
        with patch.object(runner,'run_suite',return_value=subprocess.CompletedProcess([],0,'')),redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(['--only','test_policy']),1)


if __name__=='__main__':unittest.main()
