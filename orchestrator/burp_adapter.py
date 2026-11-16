"""PM-owned Montoya bridge client. Status/history reads never send to a target.

Fresh sending uses the existing HTTP transport's guarded task-local Proxy,
not an invented Burp REST/MCP API or unscoped api.http().sendRequest().
"""
import base64
import json
import subprocess
from orchestrator import diagnostics,http_artifacts as artifacts,http_client,task_memory
from executor.netguard_root import resource_url

BROKER='/usr/local/sbin/pm-netguard'


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pm_burp_messages (
        task_id INTEGER NOT NULL,instance_id TEXT NOT NULL,message_id INTEGER NOT NULL,
        url TEXT NOT NULL,target TEXT NOT NULL,metadata_json TEXT NOT NULL,
        PRIMARY KEY(task_id,instance_id,message_id))''')


def call(task_id,value):
    with diagnostics.Action('burp','passive_read',task_id=task_id) as action:
        try:
            result=subprocess.run(['sudo','-n',BROKER,'burp-read','--task-id',str(task_id)],
                input=json.dumps(value),capture_output=True,text=True,timeout=15,
                env={**__import__('os').environ,**diagnostics.child_env()})
            payload=json.loads(result.stdout)
            if result.returncode or not isinstance(payload,dict):raise ValueError('Burp bridge unavailable')
        except (OSError,ValueError,subprocess.SubprocessError):
            payload={'status':'unavailable','reason_category':'burp_unavailable',
                'reason':'Dedicated task-local Burp Professional/Montoya bridge is not available; basic browser does not require it'}
        action.status=payload.get('status','unknown')
    return payload


def status(task_id):
    reply=call(task_id,{'action':'status'})
    if reply.get('protocol')!=3 or reply.get('edition')!='PROFESSIONAL' or reply.get('guarded_proxy') is not True:
        return {'status':'unavailable','reason_category':'burp_unavailable','reason':'Burp Professional bridge v3 with guarded Proxy is required'}
    return {**reply,'status':'available','fresh_target_request':False}


def import_history(db,task_id,url,after=0,limit=1):
    parsed,target=http_client.endpoint(db,task_id,url)
    if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=3:raise ValueError('Invalid history range')
    health=status(task_id)
    if health['status']!='available':return health
    reply=call(task_id,{'action':'history','url':url,'after':after,'limit':limit})
    if reply.get('status')!='ok' or reply.get('instance_id')!=health.get('instance_id') or not isinstance(reply.get('entries'),list) or len(reply['entries'])>limit:raise ValueError('Burp history protocol mismatch')
    initialize(db);inserted=0
    for item in reply['entries']:
        item_url,item_target=http_client.endpoint(db,task_id,item['url'],item['target'])
        if item_target!=target or item_url['origin']!=parsed['origin'] or not item_url['path'].startswith(parsed['path']):raise ValueError('Burp history resource mismatch')
        if type(item.get('id')) is not int or item['id']<=after:raise ValueError('Burp history ID invalid')
        if db.execute('SELECT 1 FROM pm_burp_messages WHERE task_id=? AND instance_id=? AND message_id=?',(task_id,health['instance_id'],item['id'])).fetchone():continue
        request=base64.b64decode(item['request_b64'],validate=True);response=base64.b64decode(item['response_b64'],validate=True)
        # Captured headers/bodies are private originals; do not merge an unknown
        # external user's cookies into any managed browser/HTTP context.
        metadata={'request_ref':artifacts.save_material(task_id,request),'response_ref':artifacts.save_material(task_id,response),
            'method':item['method'],'observed_at':item['observed_at'],'source':'burp_proxy_history',
            'format':item.get('format','montoya_http_message'),'fresh_observation':False,
            'authentication':'external history; user/session association unknown',
            'server_outcome':'uninterpreted; history import performs no target I/O'}
        metadata.update(request_material='burp:'+health['instance_id']+':'+str(item['id'])+':request',
                        response_material='burp:'+health['instance_id']+':'+str(item['id'])+':response',
                        pm_request_nonce=item.get('pm_request_nonce',''))
        db.execute('INSERT INTO pm_burp_messages VALUES(?,?,?,?,?,?)',
            (task_id,health['instance_id'],item['id'],item_url['request_url'],target,json.dumps(metadata)))
        inserted+=1
    from orchestrator.agent_actions import CAPABILITY_LOG
    task_memory.sync(db,task_id,CAPABILITY_LOG/f'task_{task_id}.jsonl',reason='passive_burp_history');db.commit()
    return {'status':'completed','imported':inserted,'fresh_target_request':False,'instance_id':health['instance_id'],
        **{key:reply[key] for key in ('scanned_through_id','skipped_oversize','has_more') if key in reply}}


def read(db,task_id):
    if not task_memory.exists(db,'pm_burp_messages'):return []
    return [{'instance_id':r[0],'message_id':r[1],'url':r[2],'target':r[3],**json.loads(r[4])} for r in db.execute(
        'SELECT instance_id,message_id,url,target,metadata_json FROM pm_burp_messages WHERE task_id=? ORDER BY instance_id,message_id',(task_id,))]
