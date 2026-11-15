"""Real PTY/Unix/TCP workers and streamed files. Only namespace/root setup replaced."""
import hashlib
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from executor import netguard_root as broker
from orchestrator import task_sessions

ROOT=Path(__file__).resolve().parents[1]


class SessionRuntimeTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='pm-session-runtime-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.directory=self.root/'s';self.directory.mkdir(mode=0o700)
        self.work=self.root/'work';self.work.mkdir(mode=0o700)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.config={'uid':os.getuid(),'gid':os.getgid(),'owner':'offline','allowed':['127.0.0.1/32'],
            'callback_override':{'bind':'127.0.0.1','advertise':'127.0.0.1','interface':'lo','reason':'local fixture'}}
        self.driver=self.root/'worker.py'
        # This is the privileged process boundary. PTY, worker protocol, input,
        # socket adoption, route reads and file streaming remain production code.
        self.driver.write_text('''import sys,os,json,subprocess
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from executor import netguard_root as b
root=Path(sys.argv[2]);kind=sys.argv[3];arguments=sys.argv[4:]
config=json.loads((root/'config.json').read_text())
b.ensure_root=lambda:None
b.owned_config=lambda task:({'name':'offline'},config)
b.session_dir=lambda task:root/'s'
b.task_workdir=lambda task,configuration:root/'work'
b.callback_paths=lambda task:(root/'callbacks',root/'state')
b.isolated_command=lambda name,user,uid,gid,args,*extra,**kw:['/usr/bin/env','PS1=PM_SESSION> ',*args]
original=subprocess.Popen
def spawn(argv,**kw):
 if argv[0]=='/usr/local/sbin/pm-netguard':return original([sys.executable,str(root/'worker.py'),sys.argv[1],str(root),*argv[1:]],**kw)
 return original(argv,**kw)
b.subprocess.Popen=spawn
realpath=os.path.realpath
b.os.path.realpath=lambda value,*a,**kw:'/usr/local/sbin/pm-netguard' if value==sys.argv[0] else realpath(value,*a,**kw)
def arg(key,default=''):
 return arguments[arguments.index('--'+key)+1] if '--'+key in arguments else default
if kind=='session-worker':b.session_worker(11,arg('session-id'),int(arg('accepted-fd','-1')))
else:b.callback_listen(11,int(arg('port')),arg('bind'),int(arg('timeout')),arg('mode','interactive'),
 None if not arg('expected-bytes') else int(arg('expected-bytes')),arg('expected-sha256'),int(arg('max-bytes','536870912')))
''')
        (self.root/'config.json').write_text(json.dumps(self.config))
        self.processes=[]
        original_popen=subprocess.Popen;realpath=os.path.realpath
        def launch(argv,**kwargs):
            if argv[0]=='/usr/local/sbin/pm-netguard':
                process=original_popen([sys.executable,str(self.driver),str(ROOT),str(self.root),*argv[1:]],**kwargs)
                self.processes.append(process);return process
            return original_popen(argv,**kwargs)
        for replacement in (patch.object(broker,'ensure_root'),patch.object(broker,'owned_config',return_value=({'name':'offline'},self.config)),
                patch.object(broker,'session_dir',return_value=self.directory),patch.object(broker,'task_workdir',return_value=self.work),
                patch.object(broker,'callback_paths',return_value=(self.root/'callbacks',self.state)),
                patch.object(broker.subprocess,'Popen',side_effect=launch),
                patch.object(broker.os.path,'realpath',side_effect=lambda value,*a,**kw:'/usr/local/sbin/pm-netguard' if value==sys.argv[0] else realpath(value,*a,**kw))):
            replacement.start();self.addCleanup(replacement.stop)
        self.addCleanup(self.stop_workers)

    def stop_workers(self):
        try:broker.callback_close(11)
        except (OSError,ValueError):pass
        for item in broker.session_list(11)['sessions']:
            try:broker.session_close(11,item['session_id'],item.get('owner',''),os.getpid())
            except (OSError,ValueError):pass
        for process in self.processes:
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()

    def test_actual_pty_can_be_released_and_used_by_another_owner(self):
        opened=broker.session_open(11,['/bin/bash','--noprofile','--norc','-i','-o','emacs'],60,'agent:first',os.getpid())
        sid=opened['session_id']
        self.assertTrue(broker.session_list(11)['sessions'][0]['running'])
        reply=broker.session_send(11,sid,"printf 'first-owner\\n'\n",0.1,'agent:first',os.getpid())
        self.assertIn('first-owner',reply['output'])
        self.assertEqual(broker.session_read(11,sid,0,'agent:second',os.getpid())['kind'],'session_busy')
        broker.session_access(11,sid,'release',owner='agent:first',owner_pid=os.getpid())
        self.assertEqual(broker.session_send(11,sid,'unused',0,'agent:second',os.getpid())['kind'],'session_read_required')
        broker.session_read(11,sid,0,'agent:second',os.getpid())
        reply=broker.session_send(11,sid,"printf 'second-owner\\n'\n",0.1,'agent:second',os.getpid())
        self.assertIn('second-owner',reply['output'])
        self.assertEqual(broker.session_close(11,sid,'agent:second',os.getpid())['status'],'closed')

    def test_actual_callback_is_bidirectional_and_disconnect_is_detected(self):
        with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
        opened=broker.callback_open(11,port,'',30)
        self.assertEqual(opened['status'],'listening',opened);self.assertEqual(opened['interface'],'lo')
        self.assertIn('waiting_no_callback',broker.callback_diagnose(11,port)['diagnosis'])
        with socket.create_connection(('127.0.0.1',port),timeout=3) as peer:
            peer.sendall(b'remote-ready\n')
            listing=[]
            for _ in range(100):
                listing=broker.session_list(11)['sessions']
                if listing and listing[0]['running'] is True:break
                time.sleep(0.02)
            self.assertTrue(listing);sid=listing[0]['session_id']
            reply=broker.session_read(11,sid,0.1,'agent:callback',os.getpid())
            self.assertIn('remote-ready',reply['output'])
            broker.session_send(11,sid,'hello-remote\n',0,'agent:callback',os.getpid())
            self.assertEqual(peer.recv(100),b'hello-remote\n')
            for _ in range(50):
                if broker.callback_diagnose(11,port)['diagnosis']=='callback_received':break
                time.sleep(0.02)
            self.assertEqual(broker.callback_diagnose(11,port)['diagnosis'],'callback_received')
        for _ in range(100):
            if not broker.session_list(11)['sessions']:break
            time.sleep(0.02)
        self.assertEqual(broker.session_list(11)['sessions'],[])

    def test_restart_recovers_spawned_worker_before_pid_was_published(self):
        opened=broker.session_open(11,['/bin/bash','--noprofile','--norc','-i','-o','emacs'],60,'agent:recovery',os.getpid())
        sid=opened['session_id'];path=self.directory/f'{sid}.json';meta=json.loads(path.read_text())
        meta.update(pid=0,process_birth='');path.write_text(json.dumps(meta))
        listed=broker.session_list(11)['sessions']
        self.assertTrue(listed[0]['running']);self.assertEqual(listed[0]['pid'],opened['pid'])
        self.assertEqual(len(self.processes),1,'Recovery must query the existing worker, not start another terminal')

    def test_continuous_terminal_output_does_not_starve_interrupt(self):
        sid=broker.session_open(11,['/bin/bash','--noprofile','--norc','-i','-o','emacs'],60,'agent:load',os.getpid())['session_id']
        reply=broker.session_send(11,sid,'yes\n',0.1,'agent:load',os.getpid())
        self.assertLessEqual(len(reply['output'].encode()),broker.SESSION_REPLY_BYTES)
        started=time.monotonic()
        reply=broker.session_interrupt(11,sid,0.1,'agent:load',os.getpid())
        self.assertEqual(reply['status'],'ok');self.assertLess(time.monotonic()-started,3)

    def test_paging_a_saved_terminal_buffer_does_not_create_new_execution_state(self):
        sid=broker.session_open(11,['/bin/bash','--noprofile','--norc','-i','-o','emacs'],60,'agent:paging',os.getpid())['session_id']
        reply=broker.session_send(11,sid,"python3 -c 'print(\"x\"*200000)'\n",0.5,'agent:paging',os.getpid())
        self.assertTrue(reply['has_more'])
        next_page=broker.session_read(11,sid,0,'agent:paging',os.getpid())
        self.assertTrue(next_page['output']);self.assertEqual(next_page['stream_state_sha256'],reply['stream_state_sha256'])

    def transfer(self,data,**kwargs):
        sender,receiver=socket.socketpair()
        def send():
            try:sender.sendall(data);sender.shutdown(socket.SHUT_WR)
            except (BrokenPipeError,OSError):pass
            finally:sender.close()
        thread=threading.Thread(target=send);thread.start()
        try:result=broker.stream_transfer(receiver,11,self.config,time.monotonic()+10,**kwargs)
        finally:receiver.close();thread.join(timeout=3)
        self.assertFalse(thread.is_alive());return result

    def test_streamed_file_exceeds_four_mib_and_verifies_size_hash(self):
        data=b'abcd'*(1300*1024)
        result=self.transfer(data,expected_bytes=len(data),expected_sha256=hashlib.sha256(data).hexdigest(),max_bytes=8*1024*1024)
        self.assertTrue(result['complete'],result);self.assertGreater(result['bytes'],4*1024*1024)
        self.assertEqual((self.work/result['file'].removeprefix('/work/')).read_bytes(),data)

    def test_unknown_size_short_file_and_disk_exhaustion_are_not_complete(self):
        self.assertEqual(self.transfer(b'abc')['completeness'],'eof_unverified_size')
        short=self.transfer(b'abc',expected_bytes=10);self.assertFalse(short['complete']);self.assertEqual(short['reason'],'size_mismatch')
        with patch.object(broker.os,'fstatvfs',return_value=type('Capacity',(),{'f_bavail':0,'f_frsize':4096})()):
            full=self.transfer(b'abc',expected_bytes=3)
        self.assertFalse(full['complete']);self.assertEqual(full['reason'],'insufficient_disk_space')
        self.assertTrue((self.work/full['file'].removeprefix('/work/')).exists())
        mismatch=self.transfer(b'abc',expected_bytes=3,expected_sha256='0'*64)
        self.assertFalse(mismatch['complete']);self.assertEqual(mismatch['reason'],'hash_mismatch')
        limit=self.transfer(b'abcdef',expected_bytes=3,max_bytes=3)
        self.assertFalse(limit['complete']);self.assertEqual(limit['reason'],'byte_budget_exhausted')

    def test_registered_transfer_tool_to_real_listener_and_preserved_file(self):
        spec=importlib.util.spec_from_file_location('streamed_transfer_mcp',ROOT/'mcp/server.py')
        server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)
        real_run=subprocess.run;data=b'streamed-file\n'*(420*1024);sha=hashlib.sha256(data).hexdigest()
        with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
        def execute(argv,**kwargs):
            if argv[:4]!=['sudo','-n','/usr/local/sbin/pm-netguard','callback']:return real_run(argv,**kwargs)
            def arg(key,default=''):return argv[argv.index('--'+key)+1] if '--'+key in argv else default
            if arg('action')=='open':reply=broker.callback_open(11,port,'',30,'transfer',int(arg('expected-bytes')),arg('expected-sha256'),int(arg('max-bytes')))
            else:reply=broker.callback_read(11)
            return subprocess.CompletedProcess(argv,0,json.dumps(reply),'')
        def call(action):
            blocks=asyncio.run(server.mcp.call_tool('pm_transfer',{'task_id':11,'action':action,'port':port,
                'expected_bytes':len(data),'sha256':sha,'max_bytes':8*1024*1024}))
            if isinstance(blocks,tuple):blocks=blocks[0]
            return json.loads(next(b.text for b in blocks if getattr(b,'type',None)=='text'))
        with patch.object(server,'ASSET_DB',self.root/'absent.db'),patch.object(server,'CAPABILITY_LOG',self.root/'caps'),\
             patch.object(subprocess,'run',side_effect=execute):
            self.assertEqual(call('open')['status'],'listening')
            with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
                client.sendall(data);client.shutdown(socket.SHUT_WR)
            for _ in range(100):
                reply=call('read')
                if reply['entries']:break
                time.sleep(0.02)
        entry=reply['entries'][0]
        self.assertTrue(entry['complete'],entry);self.assertEqual(entry['sha256'],sha)
        self.assertEqual((self.work/entry['file'].removeprefix('/work/')).read_bytes(),data)
        self.assertGreater(entry['bytes'],4*1024*1024)

    def test_transfer_is_published_only_after_receive_and_integrity_checks(self):
        owner=self
        class Stream:
            calls=0
            def settimeout(self,value):pass
            def recv(self,limit):
                self.calls+=1
                self_files=list((owner.work/'transfers').iterdir())
                owner.assertEqual(self_files,[],'In-progress bytes must not be exposed as a mutable workspace file')
                return b'abc' if self.calls==1 else b''
        result=broker.stream_transfer(Stream(),11,self.config,time.monotonic()+3,expected_bytes=3)
        self.assertTrue(result['complete']);self.assertEqual((self.work/result['file'].removeprefix('/work/')).read_bytes(),b'abc')


if __name__=='__main__':unittest.main()
