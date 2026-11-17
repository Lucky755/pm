"""Real local parsers and temporary task data; no model, network or sudo."""
import io
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
import zlib

from orchestrator import material_processing as files


def pdf_bytes(text='OFFLINE PDF ARTIFACT'):
    stream=('BT /F1 18 Tf 40 100 Td ('+text+') Tj ET').encode()
    objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',b'<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'\nendstream']
    data=b'%PDF-1.4\n';offsets=[]
    for index,body in enumerate(objects,1):offsets.append(len(data));data+=str(index).encode()+b' 0 obj\n'+body+b'\nendobj\n'
    xref=len(data);data+=b'xref\n0 6\n0000000000 65535 f \n'
    data+=b''.join(f'{offset:010} 00000 n \n'.encode() for offset in offsets)
    return data+b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+str(xref).encode()+b'\n%%EOF\n'


class MaterialTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.temp=tempfile.TemporaryDirectory(prefix='pm-material-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        p=patch.object(files,'ROOT',self.root/'materials');p.start();self.addCleanup(p.stop)
        self.db=sqlite3.connect(self.root/'task.db');self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE tasks(id INTEGER PRIMARY KEY,target TEXT)')
        self.db.executemany('INSERT INTO tasks VALUES(?,?)',[(11,'10.0.0.1'),(12,'10.0.0.2')]);self.db.commit()

    def save(self,data,name='source',source='operator:offline'):
        return files.save(self.db,11,data,name=name,source_ref=source)

    def test_actual_bytes_override_misleading_extension_and_preserve_encoding(self):
        original=self.save('Привет: сохранённый материал'.encode('utf-16'),'fake.pdf')
        result=files.process(self.db,11,original['reference'])
        self.assertEqual((result['kind'],result['status']),('text','completed'))
        text=files.load(self.db,11,result['outputs'][0]['reference']).decode()
        self.assertIn('Привет',text)
        self.assertEqual(files.load(self.db,11,original['reference']),'Привет: сохранённый материал'.encode('utf-16'))

    def test_archive_preserves_members_without_following_paths_or_executing_them(self):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as stream:
            stream.writestr('source/app.py','print("saved source")')
            stream.writestr('../escape','untrusted')
        original=self.save(archive.getvalue(),'innocent.txt')
        result=files.process(self.db,11,original['reference'])
        self.assertEqual(result['kind'],'archive');self.assertFalse(result['complete'])
        self.assertTrue(result['errors'])
        self.assertIn(b'print',files.load(self.db,11,result['outputs'][0]['reference']))
        self.assertFalse((self.root/'escape').exists())

    def test_explicit_legacy_encoding_and_corrupt_text_do_not_invent_bytes(self):
        original=self.save('Пароль не проверен'.encode('cp1251'),'note.txt')
        decoded=files.process(self.db,11,original['reference'],operation='text',options={'encoding':'cp1251'})
        self.assertEqual(decoded['status'],'completed')
        self.assertEqual(files.load(self.db,11,decoded['outputs'][0]['reference']).decode(),'Пароль не проверен')
        bad=files.process(self.db,11,original['reference'],operation='text',options={'encoding':'utf-8'})
        self.assertEqual(bad['status'],'failed');self.assertFalse(bad['complete'])

    def test_real_pdf_and_corrupt_pdf_keep_original_and_error_receipt(self):
        original=self.save(pdf_bytes(),'download.bin')
        result=files.process(self.db,11,original['reference'])
        self.assertEqual((result['kind'],result['status']),('pdf','completed'))
        self.assertIn(b'OFFLINE PDF ARTIFACT',files.load(self.db,11,result['outputs'][0]['reference']))
        corrupt=self.save(b'%PDF-1.7\nnot a PDF object','bad.pdf')
        failure=files.process(self.db,11,corrupt['reference'])
        self.assertEqual(failure['status'],'failed');self.assertFalse(failure['complete']);self.assertTrue(failure['errors'])
        self.assertTrue(any(x['metadata']['kind']=='analyzer_stderr' for x in failure['outputs']))
        self.assertEqual(files.load(self.db,11,corrupt['reference']),b'%PDF-1.7\nnot a PDF object')

    def test_image_ocr_reports_real_availability_without_a_fake_transcription(self):
        image=self.root/'scan.png'
        subprocess.run(['/usr/bin/convert','-size','900x160','xc:white','-font','DejaVu-Sans','-pointsize','48',
            '-fill','black','-gravity','center','-annotate','0','LOCAL OCR MATERIAL',str(image)],check=True,capture_output=True)
        original=self.save(image.read_bytes(),'not-an-image.txt')
        result=files.process(self.db,11,original['reference'])
        self.assertEqual(result['kind'],'image')
        binary=shutil.which('tesseract')
        languages=subprocess.run([binary,'--list-langs'],capture_output=True,text=True,check=True).stdout.splitlines() if binary else []
        if 'eng' in languages:
            self.assertEqual(result['status'],'completed')
            self.assertIn(b'LOCAL OCR MATERIAL',files.load(self.db,11,result['outputs'][0]['reference']))
        else:
            self.assertEqual(result['status'],'tool_missing');self.assertFalse(result['complete'])
            self.assertEqual(result['required_tool']['name'],'tesseract-ocr' if binary is None else 'tesseract-ocr-eng')
            self.assertEqual(result['outputs'],[])

    def test_real_static_binary_analysis_uses_binutils_not_hydra(self):
        original=self.save(Path('/usr/bin/true').read_bytes(),'specimen.txt')
        result=files.process(self.db,11,original['reference'])
        self.assertEqual((result['kind'],result['status']),('executable','completed'))
        self.assertEqual({t['tool'] for t in result['tools']},{'file','readelf','objdump','strings'})
        output=next(i for i in result['outputs'] if i['name']=='disassembly.txt')
        self.assertIn(b'Disassembly of section',files.load(self.db,11,output['reference']))

    def test_git_loose_format_hash_and_source_are_checked_without_an_extra_witness(self):
        body=b'unknown flag format in README\n';raw=b'blob '+str(len(body)).encode()+b'\0'+body;oid=hashlib.sha1(raw).hexdigest()
        original=self.save(zlib.compress(raw),'object')
        result=files.process(self.db,11,original['reference'],options={'object_id':oid})
        self.assertEqual(result['status'],'completed')
        blob=next(x for x in result['outputs'] if x['metadata'].get('object_type')=='blob')
        self.assertEqual(files.load(self.db,11,blob['reference']),body);self.assertTrue(blob['metadata']['integrity_verified'])
        bad=files.process(self.db,11,original['reference'],options={'object_id':'0'*40})
        self.assertEqual(bad['status'],'failed');self.assertIn('hash mismatch',bad['errors'][0]['reason'])
        repeated=files.process(self.db,11,original['reference'],options={'object_id':oid})
        self.assertTrue(repeated['cached']);self.assertFalse(repeated['fresh_observation'])

    def repository(self):
        root=self.root/'repository';root.mkdir()
        def git(*args):
            return subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false',
                '-c','user.name=Offline','-c','user.email=offline@example.invalid',*args],cwd=root,
                env={'PATH':'/usr/bin:/bin','HOME':str(self.root),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'},
                check=True,capture_output=True).stdout
        git('init','--template=','-b','main')
        for index in range(8):
            (root/'README.md').write_text(('common structured content '*400)+'\nrevision '+str(index))
            if index==0:
                (root/'large.dat').write_text('version https://git-lfs.github.com/spec/v1\noid sha256:'+'a'*64+'\nsize 123456\n')
                (root/'.gitmodules').write_text('[submodule "vendor"]\n path = vendor\n url = https://third-party.invalid/repository\n')
            git('add','.')
            if index==0:git('update-index','--add','--cacheinfo','160000,'+'f'*40+',vendor')
            git('commit','-m','Offline revision '+str(index))
        git('repack','-adf','--window=50','--depth=50')
        pack=next((root/'.git/objects/pack').glob('*.pack'));idx=pack.with_suffix('.idx')
        report=git('verify-pack','-v',str(idx))
        self.assertTrue(any(len(line.split())>=7 and len(line.split()[0])==40 for line in report.splitlines()))
        return root,pack,idx

    def test_native_git_pack_with_real_deltas_and_related_index(self):
        root,pack,index=self.repository()
        primary=self.save(pack.read_bytes(),'repository.pack');idx=self.save(index.read_bytes(),'repository.idx')
        result=files.process(self.db,11,primary['reference'],options={'related':[{'reference':idx['reference'],'path':'objects/pack/original.idx'}]})
        self.assertEqual(result['status'],'completed',result.get('errors'))
        self.assertTrue(any(i['metadata'].get('delta_objects',0)>0 for i in result['outputs']))
        self.assertTrue(any(b'revision 7' in files.load(self.db,11,i['reference']) for i in result['outputs'] if i['metadata'].get('object_type')=='blob'))
        self.assertTrue(any(r['kind']=='git_lfs_pointer' and not r['fetched'] for r in result['relations']))
        self.assertTrue(any(r.get('url')=='https://third-party.invalid/repository' and not r['authorized'] for r in result['relations']))
        self.assertTrue(any(r.get('submodule') and r['object_id']=='f'*40 and not r['fetched'] for r in result['relations']))
        blob=next(i for i in result['outputs'] if i['metadata'].get('object_type')=='blob' and b'revision 7' in files.load(self.db,11,i['reference']))
        selected=files.process(self.db,11,primary['reference'],options={'object_id':blob['metadata']['object_id']})
        self.assertEqual(selected['status'],'completed')
        self.assertEqual(len([i for i in selected['outputs'] if i['metadata'].get('kind')=='git_object']),1)
        self.assertTrue(any(r['kind']=='git_selection' and r['objects_omitted']>0 for r in selected['relations']))
        index_first=files.process(self.db,11,idx['reference'],operation='git',options={'related':[{'reference':primary['reference'],'path':'objects/pack/original.pack'}]})
        self.assertEqual(index_first['status'],'completed',index_first.get('errors'))

    def test_repository_archive_and_corrupt_index_are_not_guessed(self):
        root,pack,index=self.repository();archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w') as stream:stream.add(root,arcname='repo')
        original=self.save(archive.getvalue(),'repo.tar')
        result=files.process(self.db,11,original['reference'])
        self.assertEqual(result['status'],'completed',result.get('errors'));self.assertEqual(result['handler'],'archive+git')
        primary=self.save(pack.read_bytes(),'good.pack');bad=self.save(index.read_bytes()[:-20]+b'x'*20,'bad.idx')
        result=files.process(self.db,11,primary['reference'],options={'related':[{'reference':bad['reference'],'path':'objects/pack/original.idx'}]})
        self.assertEqual(result['status'],'failed');self.assertTrue(result['errors'])

    def test_foreign_and_changed_materials_are_rejected_and_migration_is_additive(self):
        original=self.save(b'original task bytes')
        with self.assertRaisesRegex(ValueError,'foreign'):files.process(self.db,12,original['reference'])
        before=self.db.execute('SELECT * FROM pm_file_materials').fetchall()
        files.initialize(self.db);files.initialize(self.db)
        self.assertEqual(before,self.db.execute('SELECT * FROM pm_file_materials').fetchall())
        (files.ROOT/'11'/original['sha256']).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'integrity'):files.process(self.db,11,original['reference'])

    def test_native_worker_denies_new_network_sockets(self):
        command='from orchestrator.material_worker import deny_network; deny_network(); import socket; socket.socket()'
        import sys
        result=subprocess.run([sys.executable,'-c',command],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertIn('Operation not permitted',result.stderr)

    def test_incomplete_source_and_publication_failure_are_not_complete(self):
        from unittest.mock import patch
        original=files.save(self.db,11,b'incomplete original',name='partial',source_ref='operator:partial',complete=False)
        result=files.process(self.db,11,original['reference'])
        self.assertEqual(result['status'],'partial');self.assertFalse(result['complete']);self.assertTrue(result['transformation_complete'])
        self.assertFalse(result['source_complete']);self.assertFalse(result['outputs'][0]['complete'])
        full=self.save('fully captured\n'.encode('utf-16'),'full')
        # Original's hash is already stored; publication alone exhausts storage.
        with patch.object(files,'MAX_TASK_BYTES',0):
            result=files.process(self.db,11,full['reference'])
        self.assertEqual(result['status'],'failed');self.assertFalse(result['complete'])
        self.assertEqual(result['errors'][-1]['category'],'publication_error')
        self.assertEqual(files.load(self.db,11,full['reference']),'fully captured\n'.encode('utf-16'))


class MaterialMCPTests(unittest.TestCase):
    def setUp(self):
        from tests import test_coordinated_attack as fixture
        from orchestrator import agent_actions
        from executor import netguard_root
        import importlib.util
        from unittest.mock import patch
        self.case=fixture.CoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        spec=importlib.util.spec_from_file_location('material_processing_mcp',Path(__file__).resolve().parents[1]/'mcp/server.py')
        self.server=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.server)
        self.workspace=self.case.root/'work'/'11';self.workspace.mkdir(mode=0o700,parents=True)
        for p in (patch.object(files,'ROOT',self.case.root/'materials'),
                  patch.object(self.server,'ASSET_DB',self.case.database),
                  patch.object(self.server,'CAPABILITY_LOG',agent_actions.CAPABILITY_LOG),
                  patch.object(netguard_root,'WORK_BASE',self.workspace.parent)):
            p.start();self.addCleanup(p.stop)

    def call(self,name,**kwargs):
        import asyncio
        reply=asyncio.run(self.server.mcp.call_tool(name,{'task_id':11,**kwargs}))
        if isinstance(reply,tuple):reply=reply[0]
        return json.loads(next(b.text for b in reply if getattr(b,'type',None)=='text'))

    def imported(self,body,name='material'):
        (self.workspace/name).write_bytes(body)
        reply=self.call('pm_material_import',path=name)
        self.assertEqual(reply['status'],'completed',reply)
        return reply['material']['reference']

    def test_public_tools_to_real_worker_memory_and_actual_prompts(self):
        from orchestrator import agent_actions as a,task_memory,target_availability
        source=b'river = "offline-fresh-candidate"\nheaders = {"Authorization": "Bearer " + river}\n'
        original=self.imported(source,'config.py')
        result=self.call('pm_material_process',reference=original)
        self.assertEqual(result['status'],'completed');self.assertFalse(result['fresh_observation'])
        derived=result['outputs'][0]['reference']
        read=self.call('pm_material_read',reference=derived)
        self.assertEqual(read['text_untrusted'],source.decode())
        with self.case.connect() as db:
            state=task_memory.source_state(db,11,a.CAPABILITY_LOG/'task_11.jsonl')
            candidates=[c for c in state['credentials'].values() if c.get('value')=='offline-fresh-candidate']
            self.assertTrue(candidates);self.assertTrue(all(c['trust']=='candidate' and not c['server_accepted'] and not c['access_implied'] for c in candidates))
            self.assertIn(derived,state['materials'])
            context=a.task_context(db,11)
            context['specialist_assignment']={'profile':'material-analysis','question':'Inspect saved authentication use site',
                'references':[derived],'expected_result':'Report exact candidate and why access remains unverified','data':[{'reference':derived,'value':state['materials'][derived]}]}
            for prompt in (a.build_prompt(db,context,'vuln','Inspect saved authentication use site',1,1,4),
                           a.compact_prompt(db,context,'vuln','Inspect saved authentication use site',1,1,4)):
                for text in ('без брутфорса',derived,'Inspect saved authentication use site','Report exact candidate','material-analysis','Hydra','Ghidra'):
                    self.assertIn(text,prompt)
                self.assertNotIn('<procedure id="browser-web">',prompt)
            target_availability.set_state(db,11,'deactivated','Target stopped',source='operator')
        repeated=self.call('pm_material_process',reference=original)
        self.assertTrue(repeated['cached']);self.assertEqual(repeated['processing_id'],result['processing_id'])
        # Neither a new file from this repository nor a secret creates a gate.
        self.assertEqual(repeated['status'],'completed')

    def test_missing_ocr_creates_durable_operator_question_and_never_installs(self):
        import base64
        from unittest.mock import patch
        from orchestrator import tool_requests,operator_questions
        from executor import netguard_root
        original=self.imported(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII='),'image.png')
        # Control executable availability, not OCR output. The real worker sees
        # the installed file parser but no OCR executable, also on OCR-capable CI.
        available=self.case.root/'visible-analyzers';available.mkdir();(available/'file').symlink_to(shutil.which('file'))
        popen=subprocess.Popen
        def launch(argv,**kwargs):
            if len(argv)>1 and str(argv[1]).endswith('material_worker.py'):
                kwargs['env']={**kwargs['env'],'PATH':str(available)}
            return popen(argv,**kwargs)
        calls=[]
        def broker(task,action,**kwargs):
            calls.append(action);self.assertEqual(action,'prepare')
            spec=netguard_root.tool_spec(kwargs['spec'])
            manifest={'task_id':task,'spec':spec,'destination':'/usr/bin/tesseract','actions':['Install exact package after operator authorization'],
                'privileges':'root package transaction','source':'configured local APT metadata'}
            return {'request_id':netguard_root.tool_digest(manifest),'manifest':manifest,'status':'prepared'}
        with patch.object(tool_requests,'broker_call',side_effect=broker),patch.object(subprocess,'Popen',side_effect=launch):
            first=self.call('pm_material_process',reference=original)
            second=self.call('pm_material_process',reference=original)
        self.assertEqual(first['status'],'tool_missing');self.assertFalse(first['complete'])
        self.assertEqual(first['operator_question']['status'],'waiting_operator')
        self.assertEqual(first['operator_question']['question_id'],second['operator_question']['question_id'])
        self.assertEqual(calls,['prepare'])
        with self.case.connect() as db:
            questions=operator_questions.listing(db,11,pending=True)
            self.assertEqual(len(questions),1);self.assertEqual(questions[0]['kind'],'tool')

    def test_workspace_import_denies_symlink_foreign_path_and_keeps_history(self):
        (self.workspace/'link').symlink_to('/etc/passwd')
        self.assertEqual(self.call('pm_material_import',path='link')['status'],'blocked')
        self.assertEqual(self.call('pm_material_import',path='../escape')['status'],'blocked')
        first=self.imported(b'first file bytes','README.md')
        second=self.imported(b'additional useful material','extra.py')
        with self.case.connect() as db:
            self.assertEqual(files.load(db,11,first),b'first file bytes')
            self.assertEqual(files.load(db,11,second),b'additional useful material')

    def test_additional_content_changes_knowledge_but_readback_and_new_ids_do_not(self):
        from orchestrator import coordinated_attack as coordinator
        with self.case.connect() as db:before=coordinator.snapshot(db,11,2)['knowledge_sha256']
        original=self.imported(b'first useful repository file','README.md')
        with self.case.connect() as db:first=coordinator.snapshot(db,11,2)['knowledge_sha256']
        self.assertNotEqual(before,first)
        self.call('pm_material_read',reference=original)
        self.imported(b'first useful repository file','readback-copy')
        with self.case.connect() as db:self.assertEqual(coordinator.snapshot(db,11,2)['knowledge_sha256'],first)
        self.imported(b'new useful source code','another.py')
        with self.case.connect() as db:self.assertNotEqual(coordinator.snapshot(db,11,2)['knowledge_sha256'],first)

    def test_unknown_format_flag_from_saved_pdf_uses_existing_operator_queue_offline(self):
        from orchestrator import flag_review,operator_questions,objectives,target_availability,coordinated_attack as coordinator,agent_actions as a
        from unittest.mock import Mock
        original=self.imported(pdf_bytes('UNUSUAL PLATFORM VALUE 4278'),'saved.pdf')
        result=self.call('pm_material_process',reference=original)
        output=next(i for i in result['outputs'] if i['metadata']['kind']=='pdf_text')
        read=self.call('pm_material_read',reference=output['reference'])
        self.assertIn('UNUSUAL PLATFORM VALUE 4278',read['text_untrusted'])
        with self.case.connect() as db:
            objectives.save_objectives(db,11,'Capture the flag',exclusive=True,expected_flags=1)
            proposal=flag_review.propose(db,11,'UNUSUAL PLATFORM VALUE 4278',objective_key='goal',
                source=output['reference'],method='Saved PDF text extraction',references=[original,output['reference'],'result:'+result['result_id']])
            question=flag_review.enqueue(db,proposal['id'])
            target_availability.set_state(db,11,'deactivated','Machine offline',source='operator')
            operator_questions.answer(db,11,question['id'],'approve','CTF platform accepted')
        model=Mock(side_effect=AssertionError('Goal already complete'))
        answer=coordinator.run(11,expect_flags=1,model=model)
        self.assertTrue(answer['succeeded']);model.assert_not_called()

    def test_real_verify_role_and_coordinator_accept_saved_transform_without_new_probe(self):
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch
        from tests.test_coordinated_attack import decision
        from orchestrator import agent_actions as a,coordinated_attack as coordinator,target_availability
        original=self.imported(b'local material witness\n','README.md')
        result=self.call('pm_material_process',reference=original)
        derived=result['outputs'][0]['reference'];rid=result['result_id']
        report={'summary':'Audited saved transformation locally; no new target action.',
            'findings':[{'title':'Saved README material','claim':'Saved bytes contain local material witness','kind':'observation',
                'quote':'local material witness','artifact_ref':derived,'probe':{'result_id':rid}}],
            'probe':{'result_id':rid,'artifact_ref':derived,'quote':'local material witness'},
            'hypotheses':[],'flags':[],'verified':[],'uncertainties':[],'proposed_actions':[]}
        class Harness:
            def __init__(self,**kwargs):pass
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def start_session(self,name):
                return SimpleNamespace(run=lambda *args,**kwargs:SimpleNamespace(events=[],finish_reason='completed',final_response=json.dumps(report)))
        with self.case.connect() as db:target_availability.set_state(db,11,'deactivated','Offline material audit',source='operator')
        choice=decision('verify','Audit saved README bytes');choice['profile']='saved-analysis'
        choice['references']=[derived];choice['inputs']=[{'reference':derived}]
        with patch.dict(sys.modules,{'deepseek_harness':SimpleNamespace(DeepSeekHarness=Harness)}), \
             patch.object(a.subprocess,'run',side_effect=AssertionError('No executor or fresh network')):
            answer=coordinator.run(11,api_key='fake-only',model=self.case.model([choice]),role_runner=a.run_role,max_steps=1)
        self.assertEqual(answer['stop_reason'],'target_restoration_required',answer)
        with self.case.connect() as db:
            saved=json.loads(db.execute("SELECT report_json FROM pm_agent_action_reports WHERE role='verify'").fetchone()[0])
            self.assertFalse(saved.get('report_incomplete'),saved.get('report_warning'))
            self.assertEqual(saved['findings'][0]['verification_status'],'local_audit')
            self.assertFalse(saved['local_audits'][0]['fresh_observation'])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pm_hypotheses WHERE status='confirmed'").fetchone()[0],0)
            # Corrupt the underlying immutable source: citation must stop validating.
            info=files.describe(db,11,int(original.split(':')[1]));(files.ROOT/'11'/info['sha256']).write_bytes(b'changed source')
            checked=a.validate_report_probes(json.loads(json.dumps(report)),11,'verify',prior_ids={rid},db=db)
            self.assertTrue(checked['report_incomplete']);self.assertEqual(checked['findings'],[])


if __name__=='__main__':unittest.main()
