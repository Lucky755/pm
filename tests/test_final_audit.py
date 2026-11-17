"""Final acceptance contracts: temporary SQLite, no provider/executor traffic."""
import json
import os
import sys
import unittest
from unittest.mock import Mock,patch
import pm
from orchestrator import coordinated_attack as c,task_runtime,report_integrity
from tests import test_coordinated_attack as fixture


class FinalAuditContracts(unittest.TestCase):
    def setUp(self):
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        p=patch.object(pm,'DB',self.case.database);p.start();self.addCleanup(p.stop)

    def test_diagnostic_flag_is_presentation_only_for_paused_resume(self):
        c.run(11,api_key='fake-only',model=Mock(return_value=json.dumps(fixture.decision(action='wait_operator'))))
        for mode in ('coordinated','legacy'):
            with self.case.connect() as db:task_runtime.save_mode(db,11,mode)
            for flags in (['--diagnostic'],['--'+mode,'--diagnostic']):
                with self.subTest(mode=mode,flags=flags),patch.object(sys,'argv',['pm','resume','11',*flags]):
                    _,args=pm.parser_main()
                    with patch.object(pm,'session_api_key',side_effect=AssertionError('No API key')), \
                         patch.object(pm,'configure',side_effect=AssertionError('No network')):
                        result=pm.op_resume(args)
                    self.assertEqual(result['status'],'waiting_operator')

    def test_http_transport_completion_is_not_an_unknown_process_exit_or_login(self):
        for complete,expected in ((True,'executed'),(False,'unknown'),(None,'unknown')):
            with self.subTest(complete=complete):
                payload={'status':'completed','status_code':401,'exchange_id':5,
                         'transport_complete':complete}
                records={'http':{'tool':'http_capture','status':'completed',
                    'capture_record':{'provenance':'network','result':payload}}}
                outcome=report_integrity.execution(records,set())
                self.assertEqual(outcome['status'],expected)
                self.assertIsNone(outcome['results'][0]['exit_code'])
                self.assertEqual(outcome['results'][0]['server_outcome'],'refused')

    def test_typed_series_completion_and_unknown_internal_check_are_distinct(self):
        for phase,expected in (('finished','executed'),('unknown','unknown')):
            payload={'status':'completed','checks':[{'phase':phase}],'checks_recorded':1,
                     'checks_started':1,'requests_sent':1,'goal_confirmed':False}
            records={'series':{'tool':'check_series','status':'completed',
                'capture_record':{'provenance':'network','result':payload}}}
            outcome=report_integrity.execution(records,set())
            self.assertEqual(outcome['status'],expected)
            self.assertNotEqual(outcome['results'][0]['server_outcome'],'accepted')

    def test_both_self_tests_use_only_temporary_paths(self):
        from orchestrator import agent_actions as a,flag_verify as f,diagnostics as d
        root=self.case.root/'self-tests'
        root.mkdir()
        with patch.multiple(a,DB_PATH=root/'tasks.db',CAPABILITY_LOG=root/'logs',
                REPORT_DIR=root/'reports',TASK_WORK_BASE=root/'work',ROLE_LOCK_DIR=root/'locks'), \
             patch.multiple(f,DB_PATH=root/'flags.db',CAPABILITY_LOG=root/'logs',POC_ROOT=root/'pocs'), \
             patch.object(d,'EVENT_DIR',root/'events'), \
             patch.dict(os.environ,{**{key:'' for key in d.ENV_KEYS},
                'PM_MODEL_AUDIT_DIR':str(root/'audit'),'PM_METHOD_LIBRARY_DIR':str(root/'methods')}):
            self.assertEqual(a.main(['self-test']),0)
            self.assertEqual(f.main(['self-test']),0)


if __name__=='__main__':unittest.main(verbosity=2)
