"""Four instruction layers. Local catalog entries can only narrow execution.

Markdown is the source of behavioral rules; runtime guards remain in code.
No database writes, model calls, procedure inference or network on composition.
"""
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]/'instructions'
ROLES=('recon','vuln','access','verify')


def common(mode='execute'):
    modes={'execute':'Use only tools allowed by the runtime for this assignment.',
           'analysis':'Tools are disabled by Harness. Analyze supplied saved data only; do not execute commands.',
           'format':'Tools are disabled by Harness. Format saved data only; do not retry operations or invent results.'}
    if mode not in modes:raise ValueError('Unknown instruction mode')
    return '<pm_common_rules>\n'+(ROOT/'PM.md').read_text().strip()+'\n</pm_common_rules>\n'+modes[mode]


def role_text(role):
    if role not in ROLES:raise ValueError('Unknown instruction role')
    return (ROOT/'roles'/f'{role}.md').read_text().strip()


def catalog():
    data=json.loads((ROOT/'profiles.json').read_text())
    tools=json.loads((ROOT/'tools.json').read_text())
    fields={'roles','purpose','inputs','procedures','tools','budget','expected_result'}
    for key,value in data.items():
        if (not re.fullmatch(r'[a-z][a-z0-9-]*',key) or not isinstance(value,dict) or set(value)!=fields
                or not value['roles'] or any(role not in ROLES for role in value['roles'])
                or not all(isinstance(value[k],str) and value[k].strip() for k in ('purpose','expected_result'))
                or not isinstance(value['inputs'],list) or not all(isinstance(v,str) and v for v in value['inputs'])):
            raise ValueError('Invalid specialist profile catalog')
        if value['tools']!='inherit' and (not isinstance(value['tools'],list) or not value['tools']
                or any(t not in tools for t in value['tools'])):
            raise ValueError('Unknown specialist tool')
        if (not isinstance(value['budget'],dict) or set(value['budget'])-{'step_limit','poc_budget','max_tokens'}
                or any(type(v) is not int or v<1 for v in value['budget'].values())):
            raise ValueError('Invalid specialist budget')
        if not isinstance(value['procedures'],list):raise ValueError('Invalid specialist procedures')
        for procedure in value['procedures']:
            if (not isinstance(procedure,str) or not re.fullmatch(r'[a-z][a-z0-9-]*',procedure)
                    or not (ROOT/'procedures'/f'{procedure}.md').is_file()):
                raise ValueError('Unknown specialist procedure')
    return data


def profile(role,selected=None):
    selected=role if selected is None else selected
    if not isinstance(selected,str):raise ValueError('unknown_profile')
    item=catalog().get(selected)
    if item is None or role not in item['roles']:raise ValueError('unknown_profile')
    return {'id':selected,**item}


def available(roles):
    return {key:value for key,value in catalog().items() if any(role in roles for role in value['roles'])}


def limits(spec,budgets):
    return {key:min(value,spec['budget'].get(key,value)) for key,value in budgets.items()}


def selected(context,role):
    assignment=context.get('specialist_assignment') or {}
    spec=profile(role,assignment.get('profile'))
    if context.get('target_availability',{}).get('network_allowed') is False:
        from orchestrator.target_availability import LOCAL_TOOLS
        spec={**spec,'tools':sorted(LOCAL_TOOLS if spec['tools']=='inherit' else LOCAL_TOOLS.intersection(spec['tools']))}
    return spec


def specialist(context,role,step_limit,poc_budget):
    spec=selected(context,role)
    effective=limits(spec,{'step_limit':step_limit,'poc_budget':poc_budget})
    block=common()+'\n\n<pm_role>\n'+role_text(role)+'\n</pm_role>'
    block+='\n\n<specialist_profile>\n'+json.dumps({**spec,'effective_budget':effective},ensure_ascii=False)+'\n</specialist_profile>'
    for procedure in spec['procedures']:
        block+='\n\n<procedure id="'+procedure+'">\n'+(ROOT/'procedures'/f'{procedure}.md').read_text().strip()+'\n</procedure>'
    return block


def tool_manual(task_id,target,spec):
    tools=json.loads((ROOT/'tools.json').read_text())
    allowed=list(tools) if spec['tools']=='inherit' else spec['tools']
    return (f'TASK_ID = {task_id}\nTARGET  = {target}\n'
            'Tool interfaces (availability is not permission; executor scope and limits still apply):\n'
            +'\n'.join(tools[name] for name in allowed))
