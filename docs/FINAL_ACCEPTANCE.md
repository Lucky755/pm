# Завершающая проверка PM

Дата: 17.11.2026. Проверенная исходная версия: `93088782a07c67a85154c8a523fd12ded9abb7b7`,
ветка `main`. Рабочие SQLite, задачи, отчёты, доказательства и сетевые настройки
не открывались тестами и не изменялись. Неотслеживаемые runtime lock-каталоги
сохранены. Модельный API — только loopback-имитатор, цели — локальные сервисы.

Дополнительная проверка на `5cfe6d6` обнаружила потерю владельца capability
при проекции в отчёт. Прежний полный PASS не проверял точную принадлежность
каждого result_id. Исправление и новые критерии описаны в
[разделе параллельного исполнения](SPECIALIST_WORKFLOW.md#принадлежность-результатов--исправление-после-5cfe6d6).

**Обозначения:** К — код/контракт с подменённой моделью или ответом исполнителя;
И — настоящая локальная интеграция указанных компонентов. И не означает проверку
установленного root-broker, VPN или настоящей CTF-платформы. Успешный контракт
не назван испытанием сетевого исполнения. Таблица фиксирует текущий результат,
а не обещание универсальной поддержки произвольного сценария.

## Матрица требований

| Требование | Реализация | Проверка | Оставшееся ограничение |
|---|---|---|---|
| 1. Разведка → находка → автоматический ACCESS | `coordinated_attack`, `specialist_workflow`, сохранённые references; прежние ACCESS/significant gates отключены | И: [сквозной new/resume](../tests/test_final_audit_runtime.py), настоящий planner/PM/SQLite/Harness/MCP/HTTP. К: [autonomous_workflow](../tests/test_autonomous_workflow.py) проверяет также legacy gates | Название роли не выдаёт разрешения; реальные NetGuard/VPN заменены на границе |
| 2. Нестандартный ответ не блокируется классификатором | Классификатор — описание; решение модели валидируется отдельно | И: необычная страница `UNUSUAL/9` в сквозном сценарии; К: `test_classifier_is_not_an_execution_gate`, `test_unusual_response_is_interpreted_by_real_role_path` | Fake API задаёт интерпретацию, качество внешней модели не измерено |
| 3. Повреждённое решение не исполняется, repair без инструментов | `model_adapter`, схема решения, ограниченное восстановление analysis | И: [model_adapter_runtime](../tests/test_model_adapter_runtime.py): настоящий SDK/MCP, отказ навязанному tool-call, испорченный JSON, raw/причина/номер попытки, нет replay. Новый сквозной тест восстанавливает JSON координатора | Возможные внутренние транспортные retries SDK не равны разрешению повторять операцию |
| 4. Кандидат → отказ → другой → принятие → конец | `flag_review`, очередь, цели проверяются до модели | И: новый сквозной CLI-сценарий с двумя кандидатами и сохранённой историей; после принятия нет API/HTTP/preflight. К: [manual_flags](../tests/test_manual_flags.py) | Ответ платформы вводит оператор; число ожидаемых флагов не уменьшается |
| 5. Неизвестный формат, нет capture, цель выключена | Явное операторское принятие отдельно от технической проверки capture | И: [operator_console_runtime](../tests/test_operator_console_runtime.py), реальный PTY/SQLite, `token=UNKNOWN_COPYABLE_FLAG` без capture при deactivated; К: manual_flags | Не является автоматическим распознаванием любого пароля как флага |
| 6. Успех третьей пары останавливает набор; пять отказов возвращают результат | Типизированная `pm_check_series`, одна пара — одна проверка | И: [work_series_runtime](../tests/test_work_series_runtime.py), зарегистрированный MCP и настоящий HTTP worker/server; новый полный Harness-сценарий останавливается на 3/5 | Поддержанный критерий Basic/HTTP не универсален для SSH/всех форм входа |
| 7. Пять серий путей, критерий, внутренние запросы | Сохраняемые directions/checks, ограничение времени/запросов; inventory отдельно от find_file | И: work_series_runtime — пять серий, первый 200 не завершает поиск, редиректы учитываются. К: [research_budgets](../tests/test_research_budgets.py) | Произвольный неинструментированный PoC не становится измеренным |
| 8. Pivot/инструмент после да/нет | Ресурсные вопросы, квитанции broker, состояние маршрута/зависимости, повторное использование | К: [task_sessions](../tests/test_task_sessions.py), [pivot_close](../tests/test_pivot_close.py), [tool_requests](../tests/test_tool_requests.py) исполняют PM/SQLite/части broker. И: [tool_download_runtime](../tests/test_tool_download_runtime.py), локальная загрузка/установка в temp | Создание настоящего SSH-forward и системная APT-установка через установленный root-broker **не проверены**; ответы SSH forward в контракте подменены |
| 9. Веб и SSH параллельно через Harness | До двух owned runtimes за общим адаптером; PM владеет памятью/целями/locks | И: [specialist_workflow_runtime](../tests/test_specialist_workflow_runtime.py), настоящий SDK/MCP stdio, HTTP и непривилегированный OpenSSH, публикация → SSH во время продолжения WEB; раздельная отмена | В SDK 0.2.1rc2 выбранного профиля native subagents/workflow недоступны; это проверенный адаптерный механизм |
| 10. Обрыв/повреждение/перезапуск без повторов | Качество отчёта отдельно от исполнения; unknown сохраняется, завершённые steps не replay | И: model_adapter_runtime — реальный tool-call и tool-free repair; operator_console_runtime — выход во время двух настоящих специалистов и восстановление паузы. К: [report_integrity](../tests/test_report_integrity.py), [operation_repeat_policy](../tests/test_operation_repeat_policy.py) | Close runtime не откатывает уже отправленную удалённую команду; unknown требует разбора |
| 11. Смена IP той же машины | `resources.rebind`, тот же task ID, оригиналы/цели/вопросы сохраняются | К: [resource_scope](../tests/test_resource_scope.py), реальные PM change-ip/resume/SQLite с подменой внешнего IO, один preflight без tcp_full | Настоящие VPN/IP/IPv6-маршруты и firewall в этом тесте не изменяются |
| 12. HTTP/JS/редиректы/SSRF | Общий HTTP, отдельные user sessions, Playwright через scoped transport | И: [24 HTTP runtime-проверки](../tests/test_http_client_runtime.py), [11 Chromium/JS/CSRF](../tests/test_browser_runtime.py), включая SSRF через настоящее loopback-приложение. К: scope/resources | SSRF проверяет разрешённое приложение/назначение; не универсальный HTTP/браузер/SSRF движок. Живой Burp Pro не проверен |
| 13. Выключенная цель: без повторной сети, локальные материалы доступны | `target_availability`, локальные чтения, ранняя проверка целей | И: новый сквозной сценарий и PTY-подтверждение; [port_research](../tests/test_port_research.py) использует локальные TCP/UDP. К: deactivated/локальная аналитика и guard | Ping/тайм-аут не доказывает выключение; объявление deactivated принадлежит оператору |
| 14. Бюджет продлевается и сохраняется | SQLite base/granted/used; +5 через очередь, 15 coordinator / 25 specialist, PoC 15 | К: 16 research_budgets, настоящий PM/SQLite/MCP и Node gate, повторное открытие БД | Не измеряет все внутренние действия произвольной утилиты; длительная операция ограничена своим timeout |
| 15. Релевантная память, агрегация без модели, честные токены | CAS/revisions/index/coverage; полный inventory отдельно от prompt sample; статистика адаптера | К: [29 task_memory](../tests/test_task_memory.py), [20 service_inventory](../tests/test_service_inventory.py), инструкции/контекст. И: model_adapter_runtime — фактический запрос SDK, чтение MCP, наблюдаемое cache usage и unknown | Fake API проверяет передачу счётчиков, **не** реальный cache hit/экономию провайдера; размеры счёта не оценивались |

## Дополнение: владельцы результатов после `5cfe6d6`

- Исходный HEAD `5cfe6d6aab713da9eab87bc53feb1232fa08766c`, ветка main.
  Рабочие SQLite/отчёты/доказательства не открывались и не переписывались;
  неотслеживаемые lock-каталоги сохранены. Миграций схемы нет.
- Проверены все звенья: MCP JSONL → report_probe_records → execution/repair →
  валидация findings, гипотез, доступа/триажа → канонический отчёт SQLite/JSON →
  общая память и локальное MCP-чтение. Исходные prior IDs остаются неизменным
  снимком начала хода; чужие и неатрибутированные записи исключаются отдельно.
  Новые чужие данные во время repair не обходят фильтр.
- Собственный успех + чужой unknown остаётся собственным успехом; unknown
  сохраняется в отчёте своего владельца. Чужой успех не создаёт собственный
  зонд/доступ/закрытие гипотезы. Полезный чужой capture доступен для локального
  аудита без GET и без дополнительного независимого подтверждения.
- Исторические строки без владельца остаются читаемыми с явной отметкой
  unestablished. Coordinated не приписывает им текущий step ID. Исторические
  канонические отчёты не исправлялись задним числом по догадке.
- До исправления: новая контрактная регрессия воспроизвела собственный success
  + foreign timeout → unknown и потерю owner. Настоящий runtime воспроизвёл
  чужие result_id в обоих профилях/ролях; два из четырёх сценариев упали на
  новых assertions принадлежности. Это отдельное доказательство дефекта,
  а не подмена его подсчётом tool_calls.
- После исправления: 12 новых контрактных проверок и усиленные 4 настоящих
  runtime-сценария. Они синхронизируют сохранение квитанций и сравнивают каждый
  result_id с coordinator_step_id/actor_role. Общий VULN-бюджет равен 5 при
  отдельных расходах 3 и 2. Все хранилища временные, API — loopback fake,
  HTTP/OpenSSH/Harness/MCP — настоящие; привилегированные IO заменены.

Команды воспроизведения:

```bash
.venv/bin/python tests/run_offline.py --only test_result_ownership test_final_audit
.venv/bin/python tests/run_offline.py --runtime --only test_specialist_workflow_runtime
.venv/bin/python tests/run_offline.py --runtime
```

Логи этого исправления (вне Git): `/tmp/pm-result-ownership-before.log`,
`/tmp/pm-result-ownership-runtime-before.log`,
`/tmp/pm-result-ownership-runtime-after.log`,
`/tmp/pm-result-ownership-full.log` (первый полный прогон: два сбоя фикстур),
`/tmp/pm-result-ownership-full-final.log` (финальный полный прогон).
Результат: **845 тестов, 0 skipped, 6 legacy scripts, 0 failed suites**.
Связанный финальный набор — **76 тестов**, отдельно **4 runtime-сценария**;
ownership + обе self-test — **16 тестов**, без пропусков/сбоев.
Первый полный прогон выявил два старых тестовых источника без owner; фикстуры
исправлены передачей меток настоящего вызова без изменения assertions.
check_environment compatible=true, pip check, compileall, Node syntax двух
политик и git diff --check — PASS. Обе self-test входят в test_final_audit с
временными путями под storage guard. Настоящие CTF/VPN/root-broker/платный API, native
workflow и ранее перечисленные необязательные интеграции этим исправлением
не испытаны и не объявляются прошедшими.

## Найденные и исправленные интеграционные дефекты предыдущей проверки

1. `resume --diagnostic` отклонял показ уже сохранённой паузы как изменение
   параметров исполнения. Флаг добавлен только к разрешённым флагам отображения
   обеих paused-веток. Запрос ключа, preflight, сеть и модель при просмотре не нужны.
2. `report_integrity.execution()` требовал process exit_code и называл завершённые
   HTTP-запросы/типизированные серии неизвестным исходом. Теперь используются
   явные typed receipts: HTTP transport_complete + exchange_id либо завершённые
   внутренние checks серии. `agent_actions.report_probe_records()` сохраняет эти
   поля в своём представлении; из checks передаётся только phase. Отсутствующий
   exit_code остаётся отсутствующим, HTTP 401 — отказом сервера, а не ошибкой
   запуска; выполнение не подтверждает вход, shell или цель. Без квитанции либо
   при unknown-внутренней проверке исход остаётся unknown.

[Регрессии](../tests/test_final_audit.py) сначала воспроизвели обе ошибки.
Самостоятельный runtime-тест дополнительно воспроизвёл потерю typed-полей
между capability log и каноническим отчётом. Исправления не меняют доказательства,
разрешения, бюджеты, порядок сетевых действий или рабочую схему.

## Порядок воспроизведения

Из корня checkout с установленными совместимыми зависимостями:

```bash
.venv/bin/python -m orchestrator.check_environment
.venv/bin/python -m pip check
.venv/bin/python tests/run_offline.py --runtime --only test_final_audit test_final_audit_runtime --verbose
.venv/bin/python tests/run_offline.py --runtime
.venv/bin/python -m compileall -q pm.py orchestrator executor mcp tests
node --check orchestrator/agent_actions.mjs
node --check orchestrator/evidence_readonly.mjs
git diff --check
```

Runner запускает отдельные процессы под storage guard; skip выбранного теста
не считается успехом. Runtime требует loopback/Unix sockets, PTY, Chromium,
локальные sshd/ssh и установленный SDK. Запрет сокетов окружением — ограничение
среды, а не причина заменить runtime моками или объявить его пройденным.
В `test_final_audit` входят обе настоящие self-test (`agent_actions` и
`flag_verify`) с временными DB/log/report/work/lock путями. Не запускайте их
на рабочих путях вместо этой проверки.

Новый runtime начинает с пустого файла БД. [scheduler_first_run](../tests/test_scheduler_first_run.py)
отдельно проходит старую минимальную схему: сохранённая задача → tcp_full →
follow-up → успешный preflight → настоящие call_scheduler/auto/make_snapshot →
раунд → штатная остановка, затем повторная инициализация и продолжение без
повторного tcp_full/дублирования. Его скан/preflight — подмена executor IO,
не настоящий Nmap. Миграции памяти/HTTP проверены на временных старых схемах.

Короткая трасса нового настоящего SDK/MCP-сценария:

```text
empty DB -> planner -> malformed decision -> analysis repair (no tools)
RECON -> /credentials -> ACCESS (no approval): bad1 / bad2 / secret3: stop 3/5
candidate #1 -> operator decline -> VULN -> candidate #2
target deactivated -> operator approve #2 -> resume --diagnostic -> goal complete
no extra model request / GET / preflight; expected_flags remains 1
```

### Результат запуска 17.11.2026

Исходный набор: **828 тестов, 0 skipped, 6 legacy scripts, 0 failed suites**.
Новый контрактный набор вместе со схемой/памятью: **37 тестов**, включая обе
self-test; runtime-сценарий — отдельно **1 тест**, без пропусков.
Полный финальный набор: **833 теста, 0 skipped, 6 legacy scripts, 0 failed suites**.
Обе self-test входят в этот запуск через новые контракты. Дополнительный повтор
новых контрактов проверяет и legacy/coordinated paused-view.
`check_environment`: compatible=true; `pip check`: No broken requirements found;
compileall, Node syntax двух политик и `git diff --check`: PASS.
Реальный Montoya API JAR 2026.7: компиляция Java и HMAC/path/single-use контракт
прошли; это отдельно от непроведённой живой проверки Burp.

Логи разработки (вне Git): `/tmp/pm-final-acceptance.log` (полный набор),
`/tmp/pm-final-acceptance-trace.log` (новые тесты с трассой),
`/tmp/pm-final-audit-schema-selftests.log` (схемы/память/self-test).
Отрицательные воспроизведения: `/tmp/pm-final-audit-regression-before.log`
и `/tmp/pm-final-audit-http-before.log`. Эти временные логи не являются архивом
рабочей задачи и могут исчезнуть после перезагрузки.

Непроверенные необязательные интеграции: настоящий Burp Suite Professional,
Ghidra/headless decompiler, реальный Tesseract/OCR (здесь tesseract отсутствует;
проверяется tool-missing путь), внешняя CTF-платформа. Контракт guarded Proxy/CONNECT
не подменяет запуск Pro. Платный API и настоящий кэш провайдера не использовались.
Root-owned broker/iptables/netns/VPN, системная установка пакетов и реальный
pivot forward также не были частью локального runtime. Одна Kali, один оператор,
нет фонового демона, Orca, второго хранилища состояния или новых провайдеров.

## Короткая живая проверка — только отдельным операторским запуском

1. Сохранить приватный backup и журналы; проверить версии/зависимости. Оператор
   отдельно сверяет установленный root-broker с поддержанными протоколами,
   изоляцию/VPN и условия комнаты. Эта разработка broker не переустанавливает.
2. Выбрать одну разрешённую цель, область web/host и явные условия, expected_flags
   и бюджеты. Ввести ключ штатным getpass, не argv. Начать с одного специалиста;
   затем отдельным решением проверить два независимых направления.
3. Убедиться, что URL не вызывает полный скан общего IP, находка переходит в
   конкретную проверку без ACCESS/significant-паузы; проверить result_id/original.
4. Проверить один конкретный вопрос tool/pivot: границы, Да/Нет, квитанция,
   отсутствие повторного выполнения. Privileged/live части пока не приняты
   локальными тестами и требуют именно этого отдельного разрешённого испытания.
5. Кандидат отправляется оператором на платформу: отказ не завершает цель,
   принятие всех целей завершает до следующего модельного запроса. При выключении
   машины явно выставить target-state и проверить локальный маршрут.
6. Выйти штатно, осмотреть незавершённые действия, просмотреть сохранённую паузу.
   Очистку сетевых правил выполнять отдельным явным действием после сохранения
   материалов, не автоматически при паузе/неуспехе.

## Сбор диагностических материалов

Сначала штатно остановить ручной запуск и его модельные workers. Один SQLite
backup согласован, но одновременно изменяемые файлы не образуют общего снимка
с БД. Не копировать только основной `.db` мимо SQLite, игнорируя WAL.

Следующая команда — **для отдельного операторского сбора**, здесь на рабочей
БД не выполнялась. Она открывает источник read-only без PM/migrations, проверяет
целостность только копии и создаёт приватный каталог вне checkout:

```bash
umask 077
.venv/bin/python - <<'PY'
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
root = Path.home() / 'pm-support' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
root.mkdir(parents=True, mode=0o700)
source = Path('storage/tasks.db').resolve()
with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as src:
    with closing(sqlite3.connect(root / 'tasks.sqlite3')) as dst:
        src.backup(dst)
        result = dst.execute('PRAGMA integrity_check').fetchall()
        (root / 'integrity.txt').write_text(repr(result) + '\n')
print(root)
PY
```

В этот каталог явно скопировать данные **нужной задачи/ручных run_id**:

- `storage/run_events/RUN_ID.jsonl` (run_id/path напечатан в конце запуска);
- соответствующие metadata/raw из `storage/run_events/model_requests/` либо
  `storage/model_requests/` — каталог указан в событиях адаптера;
- `storage/agent_reports/task_ID/` с `.json`, `.raw.txt`, `.format.raw.txt`;
- `storage/capability_log/task_ID.jsonl`, необходимые `artifacts/http/task-ID/`
  и `artifacts/materials/ID/`; при необходимости — выбранные workspace/PoC
  этой задачи. Оригиналы не заменять короткими console summaries;
- текст консоли, HEAD/ветку, вывод check_environment/pip check и точные аргументы
  запуска без ключей. Полные окружения, key-файлы и Harness-конфиги не собирать.

Точные пути raw/result брать из сохранённых ссылок. Не редактировать исходники
доказательств ради выгрузки. Backup содержит также другие задачи; HTTP/отчёты
могут содержать пароли, cookies и флаги. Это приватный локальный пакет, не файлы
для Git/автоматической отправки; для передачи отдельно готовится обезличенная копия.
Добавить manifest размеров/SHA-256 скопированных файлов и сохранить отдельно
от рабочих данных. Сбор пакета не восстанавливает состояние после прежнего
инцидента БД и не меняет исторические статусы или expected_flags.
