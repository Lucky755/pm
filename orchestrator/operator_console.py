"""Human presentation and a single TTY reader; no task policy or task-state mirror.

Journals and original results remain owned by diagnostics/executor. Only the
coordinator run owns model runtimes; the terminal asks it to stop explicitly.
"""
import codecs
import json
import os
import select
import sqlite3
import sys
import termios
import threading
import tty
from contextvars import copy_context


def safe(value,limit=240):
    from orchestrator.diagnostics import clean
    return clean(value,limit=limit)


def reason(value):
    code=str(value or 'unknown')
    labels={'target_restoration_required':'цель выключена/недоступна; работа с сохранёнными материалами',
        'operator_questions_pending':'ожидание ответа оператора', 'coordinator_budget_exhausted':'исчерпан бюджет координатора',
        'specialist_budget_exhausted':'исчерпан бюджет специалиста', 'coordinator_step_limit':'достигнут предел шагов запуска',
        'flag_confirmed':'все требуемые флаги приняты оператором после проверки на платформе',
        'objectives_done':'все сохранённые цели выполнены', 'goal_confirmed':'сохранённая цель подтверждена',
        'role_report_damaged_requires_review':'действие и качество отчёта разделены: отчёт повреждён',
        'role_report_incomplete_requires_review':'отчёт неполон; исход требует проверки',
        'interrupted_running_step':'после прерывания остался шаг с неизвестным исходом',
        'model_stopped_incomplete':'новых действий не выбрано; цели ещё не подтверждены',
        'all_directions_exhausted':'рассмотренные направления исчерпаны; это не достижение цели',
        'no_independent_work_available':'сейчас нет независимой полезной работы',
        'interrupted':'выход оператора; незавершённые действия сохранены',
        'completed':'запуск завершён; это само по себе не подтверждает цель',
        'budget_exhausted':'исчерпан бюджет; требуется явное продление', 'target_offline':'цель выключена; только сохранённые материалы',
        'timeout':'тайм-аут; исход операции неизвестен', 'outcome_unknown':'исход операции неизвестен',
        'scope_denied':'действие вне разрешённой области', 'executor_unavailable':'исполнитель недоступен',
        'permission_denied':'недостаточно прав', 'policy_refusal':'действие отклонено до исполнения',
        'nonzero_exit':'команда выполнена с ненулевым кодом возврата', 'server_refusal':'сервер отказал в операции'}
    return labels.get(code,safe(code))


def event_lines(e):
    kind=e['kind'];role=e.get('role');who=('['+safe(str(role).upper(),40)+'] ') if role else ''
    if kind=='model.request_start':return [who+'Анализ: выбираю следующий шаг.' if e.get('mode')=='analysis' else who+'Анализ: выполняю поручение специалиста.']
    if kind=='model.request_end' and e.get('status') not in ('completed','max-tokens'):
        return [who+'Запрос модели завершён: '+safe(e.get('status'))+' · полный результат '+safe(e.get('audit_path'))]
    if kind=='coordinator.decision':
        return [who+'Следующий шаг: '+safe(e.get('question')),
                '  Ожидаемый результат: '+safe(e.get('expected_result'))]
    if kind=='tool.start':
        params=e.get('parameters') or {};detail=' '.join(f'{k}={safe(params[k],80)}' for k in ('target','port','profile','action','executable') if k in params)
        return [who+'Действие: '+safe(e.get('name'),80)+(' · '+detail if detail else '')]
    if kind=='tool.end':
        status=e.get('status');label={'completed':'операция выполнена; смысл ответа требует проверки',
            'nonzero_exit':'операция выполнена с ненулевым exit_code','blocked':'отказ до исполнения',
            'error':'ошибка исполнителя','timeout':'тайм-аут; исход неизвестен','unknown':'исход неизвестен',
            'outcome_unknown':'исход неизвестен','waiting_operator':'ожидание ответа',
            'abandoned':'исход неизвестен после прерывания','interrupted':'операция прервана; проверьте исход'}.get(status,safe(status))
        if e.get('server_outcome')=='refused':label='сервер отказал; вызов инструмента выполнен'
        if e.get('reason_category')=='target_offline':label=reason('target_offline')
        result=[who+'Результат: '+label+' · '+safe(e.get('name'),80)+f" · {e.get('duration_seconds',0)} с"]
        if e.get('reason_summary'):result.append('  Причина: '+safe(e['reason_summary']))
        if e.get('result_id'):result.append('  Полный результат: '+safe(e.get('evidence_path') or e['result_id']))
        if e.get('exit_code') is not None:result[-1]+=' · exit_code='+str(e['exit_code'])
        if e.get('status_code') is not None:result[-1]+=' · HTTP '+str(e['status_code'])+' (статус не доказывает вход)'
        return result
    if kind=='report.saved':
        return [who+'Отчёт сохранён: '+safe(e['report_path']),
                '  '+('Отчёт повреждён; исход действия учитывается отдельно.' if e.get('quality')=='damaged' else
                      'Отчёт неполон; исход требует проверки.' if e.get('incomplete') else 'Завершение роли не означает достижение цели.'),
                *(['  Новые сведения: '+safe(e['facts'])] if e.get('facts') else [])]
    if kind=='coordinator.pause':return ['Ожидание: '+reason(e.get('reason')), *(['  Полный ответ: '+safe(e['raw_report_path'])] if e.get('raw_report_path') else [])]
    if kind=='model.retry':return [who+'Модель: ограниченное восстановление · '+safe(e.get('reason'))]
    if kind in ('check.start','check.end'):
        identity=safe((e.get('identifiers') or {}).get('check_id') or e.get('check_id'))
        status={'criterion_matched':'критерий выполнен; цель учитывается отдельно','negative':'критерий не выполнен',
            'server_refusal':'сервер отказал','unknown':'исход неизвестен'}.get(e.get('status'),safe(e.get('status')))
        return [who+'Внутренняя проверка '+identity+(': начата' if kind.endswith('.start') else ': '+status)]
    if kind=='poc.checks':return [who+f"Проверки PoC: начато {e['started']}, завершено {e['finished']}; " +
        ('не все исходы известны' if e['started']!=e['finished'] else 'результаты сохранены')+' (самоотчёт кода)']
    if kind=='memory.published':return [who+'Новые сведения: опубликован кандидат; принятие сервером и доступ ещё не подтверждены.']
    if kind=='state.change' and e.get('table')=='pm_access_state':
        current=e.get('current_state') or {}
        return [who+'Новые сведения о доступе: '+safe(current.get('level'))+' / '+safe(current.get('signal'))+
                ' · доказательство '+safe(e.get('result_id'))]
    if kind=='specialist.cancelled':return [who+'Специалист остановлен: '+reason(e.get('reason'))+'; исход начатых действий сохранён отдельно.']
    if kind=='run.summary':
        return ['Итог: '+reason(e.get('reason')), 'Незавершённых действий: '+str(len(e.get('unfinished') or [])),
                'Журнал запуска: '+safe(e.get('journal'),None)]
    return []


def question_lines(q):
    result=[f"Вопрос #{q['id']} [{safe(q['status'])}] · {safe(q['kind'])} · ветка {safe(q['branch_id'])}",
        '  '+safe(q['question']), '  Причина: '+safe(q['reason'])]
    bounds=q.get('boundaries') or {}
    result.append('  Границы: задача '+str(bounds.get('task_id',q['task_id']))+' · '+safe(bounds.get('target',q.get('target','')))+
        ' · ресурсы '+', '.join(safe(v) for v in bounds.get('resource_refs',[]))+' · ограничения исходного задания сохранены')
    grant=q.get('budget_request')
    if grant:result.append('  Счёт: '+safe(grant['category'])+'/'+safe(grant['actor'])+f" · +{grant['amount']} к {grant['previous_limit']}")
    tool=q.get('tool_request')
    if tool:
        spec,manifest=tool['spec'],tool['manifest']
        result.extend(['  Назначение: '+safe(spec['purpose']),'  Источник: '+safe(spec.get('source','настроенный APT')),
            '  Версия: '+safe(spec['version']), '  Место установки: '+safe(manifest.get('host_destination',manifest.get('destination',''))),
            '  Права: '+safe(manifest.get('privileges',''))])
        for action in manifest.get('actions',[]):result.append('  Действие установки: '+safe(action if isinstance(action,str) else action.get('action') or action.get('operation') or 'см. квитанцию'))
    route=q.get('pivot_request')
    if route:
        if route.get('diagnostic'):result.append('  Маршрут: '+safe(route['diagnostic']['reason_summary']))
        else:
            spec=route['receipt']['manifest']['spec']
            result.append('  Маршрут: '+safe(spec['source_session'])+' → '+safe(spec['destination'])+':'+str(spec['port']))
    candidate=q.get('flag_candidate')
    if candidate:
        value=candidate['value']
        from orchestrator import diagnostics
        # Keys may not become visible even if misclassified as a flag candidate.
        if any(secret in value for secret in diagnostics._secrets):
            result.append('  Значение скрыто: содержит зарегистрированный API-ключ.')
        else:
            result.append('  Точное значение (JSON): '+json.dumps(value,ensure_ascii=True))
            if value and value.strip()==value and not any(ord(c)<32 or 127<=ord(c)<=159 for c in value):result.append('  Для копирования: '+value)
        result.append('  Цель: '+safe(candidate['objective_key'])+' · '+safe(candidate['objective_title']))
        for source in candidate['sources']:result.append('  Источник: '+safe(source['source'])+' · способ '+safe(source['method']))
        result.append('  Материалы: '+', '.join(safe(ref) for ref in candidate['materials']))
    consequences={'flag_confirmation':('оператор проверил флаг на платформе; выполнится только связанная цель','кандидат отклонён; поиск продолжается без повторного GET'),
        'budget':('добавятся ровно 5 единиц названного счёта; scope прежний','бюджет не увеличится; другое направление'),
        'tool':('одобрена только указанная квитанция; применение отдельной операцией','инструмент не устанавливается; нужен другой способ'),
        'pivoting':('одобрена только указанная связь; применение отдельной операцией','маршрут не создаётся; нужен другой путь')}
    yes,no=consequences.get(q['kind'],('сохранён явный ответ в этих границах','действие не одобрено'))
    result+=['  Да: '+yes+'.','  Нет: '+no+'.',f"  Ответ: да {q['id']} / нет {q['id']} (ID обязателен)."]
    return result


class LiveSession:
    """One stdlib cbreak reader; concurrent complete lines redraw typed input.

    Starts lazily after key acquisition. No stdin readers in agent workers.
    Uses only the supplied existing question/answer and runtime stop mechanisms.
    """
    prompt='pm [вопросы | да ID | нет ID | статус | выход] > '
    def __init__(self,control,questions,answer,*,input_stream=None,output=None,enabled=True):
        self.control,self.questions,self.answer=control,questions,answer
        self.input=input_stream or sys.stdin;self.output=output or sys.stdout
        self.enabled=enabled and self.input.isatty() and self.output.isatty()
        self.lock=threading.RLock();self.done=threading.Event();self.started=False;self.buffer='';self.seen=set();self.pending={}
        self.original_streams=None;self.reader=None

    def start(self):
        if not self.enabled or self.started:return
        self.fd=self.input.fileno();self.attributes=termios.tcgetattr(self.fd)
        tty.setcbreak(self.fd)
        self.started=True
        self.original_streams=sys.stdout,sys.stderr
        sys.stdout=sys.stderr=self
        self.reader=threading.Thread(target=copy_context().run,args=(self.read_loop,),name='pm-operator-input')
        self.reader.start()

    def isatty(self):return False # no untrusted ANSI; redraw uses the actual TTY only
    @property
    def encoding(self):return 'utf-8'
    def writable(self):return True
    def write(self,chunk):
        with self.lock:
            ident=threading.get_ident();text=self.pending.get(ident,'')+str(chunk)
            while '\n' in text:
                value,text=text.split('\n',1);self.output.write('\r\x1b[2K'+safe(value,None)+'\n');self.draw()
            self.pending[ident]=text
        return len(chunk)
    def flush(self):
        with self.lock:self.output.flush()
    def draw(self):
        if not self.done.is_set():self.output.write('\r\x1b[2K'+self.prompt+safe(self.buffer,None));self.output.flush()
    def say(self,text,*,prepared=False):
        if prepared:
            # question_lines already scrubs metadata and escapes literal values;
            # generic password= masking must not change the exact flag value.
            with self.lock:
                self.output.write('\r\x1b[2K'+text+'\n');self.draw();self.output.flush()
        else:self.write(text+'\n');self.flush()

    def show_questions(self,force=False):
        for q in self.questions():
            key=(q['id'],q['status'])
            if force or key not in self.seen:
                self.seen.add(key)
                for line in question_lines(q):self.say(line,prepared=True)

    def command(self,raw):
        parts=raw.strip().lower().split()
        if not parts:return
        if parts==['выход'] or parts==['exit'] or parts==['quit']:
            self.say('Выход: прекращаю модельную работу; история и сетевые правила сохраняются.');self.control.stop();return
        if parts in (['вопросы'],['questions'],['статус'],['status']):self.show_questions(True);return
        if len(parts)!=2 or parts[0] not in ('да','нет','yes','no') or not parts[1].isdigit():
            self.say('Нужно: да ID / нет ID, вопросы, статус или выход. Ответ без ID не применяется.');return
        qid=int(parts[1]);q=next((q for q in self.questions() if q['id']==qid and q['status']=='pending'),None)
        if not q:self.say('Нет ожидающего вопроса с выбранным ID; ответ не применён.');return
        self.answer(qid,'approve' if parts[0] in ('да','yes') else 'decline')
        self.say('Ответ на вопрос #'+str(qid)+' сохранён. Независимые ветки продолжают работу.')

    def read_loop(self):
        decoder=codecs.getincrementaldecoder('utf-8')()
        try:
            self.draw()
            while not self.done.is_set() and not self.control.stopped.is_set():
                try:self.show_questions()
                except (ValueError,OSError,sqlite3.Error) as exc:
                    if ('queue',type(exc).__name__) not in self.seen:
                        self.seen.add(('queue',type(exc).__name__));self.say('Очередь временно недоступна: '+safe(type(exc).__name__)+'; выполнение не изменено.')
                if not select.select([self.fd],[],[],.1)[0]:continue
                raw=os.read(self.fd,1024)
                if not raw:self.control.stop();return
                for char in decoder.decode(raw):
                    if char in ('\r','\n'):
                        with self.lock:
                            command=self.buffer;self.buffer='';self.output.write('\r\x1b[2K'+self.prompt+safe(command,None)+'\n')
                        try:self.command(command)
                        except (ValueError,OSError,sqlite3.Error) as exc:self.say('Ответ не применён: '+safe(exc))
                    elif char in ('\x7f','\b'):
                        with self.lock:self.buffer=self.buffer[:-1];self.draw()
                    elif char=='\x04':self.control.stop();return
                    elif ord(char)>=32 and char!='\x1b':
                        with self.lock:self.buffer+=char;self.draw()
        except Exception as exc:
            try:self.say('Ввод оператора недоступен: '+safe(type(exc).__name__))
            except (OSError,ValueError):pass
            finally:self.control.stop()

    def close(self):
        self.done.set()
        if self.reader and self.reader.ident is not None:self.reader.join()
        if self.started:
            try:termios.tcsetattr(self.fd,termios.TCSADRAIN,self.attributes)
            except (OSError,termios.error):pass # a disconnected terminal cannot be restored
            finally:sys.stdout,sys.stderr=self.original_streams
            try:
                with self.lock:
                    self.output.write('\r\x1b[2K')
                    for value in self.pending.values():
                        if value:self.output.write(safe(value,None)+'\n')
                    self.output.flush()
            except (OSError,ValueError):pass
