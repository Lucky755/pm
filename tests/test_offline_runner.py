"""Inventory and process isolation checks without importing test subjects."""
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import unittest
import tempfile
import os
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
            self.assertEqual(call.kwargs['env']['PYTHONPATH'].split(os.pathsep)[-1],str(runner.ROOT))
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

    def test_working_storage_guard_blocks_sqlite_before_modification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'storage').mkdir();database=root/'storage/tasks.db'
            database.write_bytes(b'original untouched bytes');before=database.read_bytes()
            env={**os.environ,'PYTHONPATH':runner.storage_guard(root,workspace=root)}
            reply=subprocess.run([sys.executable,'-c','import sqlite3,sys;sqlite3.connect(sys.argv[1])',str(database)],
                                 env=env,capture_output=True,text=True)
            self.assertNotEqual(reply.returncode,0);self.assertIn('Offline test attempted working storage access',reply.stderr)
            self.assertEqual(database.read_bytes(),before)
            descriptor=os.open(root/'storage',os.O_RDONLY|os.O_DIRECTORY)
            try:
                reply=subprocess.run([sys.executable,'-c','import os,sys;os.open("tasks.db",os.O_RDWR,dir_fd=int(sys.argv[1]))',str(descriptor)],
                    env=env,pass_fds=(descriptor,),capture_output=True,text=True)
                self.assertNotEqual(reply.returncode,0);self.assertIn('Offline test attempted working storage access',reply.stderr)
            finally:os.close(descriptor)
            self.assertEqual(database.read_bytes(),before)


if __name__=='__main__':unittest.main()
