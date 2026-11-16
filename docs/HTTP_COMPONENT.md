# HTTP-компонент задачи

Реализовано от `3ac2a80`. Основной путь специалиста — зарегистрированный MCP
`pm_http_request(task_id, request_json, session_id="default")`. Он всегда
получает свежий ответ; `pm_http_read` читает ранее сохранённый обмен и никогда
не обращается к цели. Legacy `pm_http_capture`/`pm_http_ssrf` сохраняют явную
совместимость с кэшем начальной GET-разведки; для проверки текущего состояния
они не подставляются вместо нового компонента.

## Запрос и веб-сессия

```json
{
  "url": "http://app.lab:8080/login?next=%2Faccount#browser-only",
  "method": "POST",
  "query": [["source", "room"], ["tag", "one"], ["tag", "two"]],
  "headers": {"Accept": "application/json"},
  "form": {"username": "student", "password": "candidate"}
}
```

Поддержаны GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS и корректные имена HTTP-методов
(например WebDAV); CONNECT и upgrade/туннелирование не поддержаны. Query сохраняет
повторяющиеся параметры/порядок; fragment не отправляется серверу. Host/SNI
определяются URL и сохранёнными address pins, отдельный произвольный Host не
обходит scope. DNS нового редиректа не запрашивается для получения разрешения.

Выбирается один способ тела: UTF-8 `body`, бинарный `body_b64`, `json` (включая
null), URL-encoded `form` либо multipart `form` + `files`. Заголовки передаются
объектом либо парами; framing/длина/authority формируются транспортом. CR/LF,
неоднозначные security-заголовки и ручной Transfer-Encoding отклоняются.

```json
{"url":"http://app.lab:8080/upload","method":"POST",
 "form":{"purpose":"room evidence"},
 "files":[{"field":"file","path":"/work/proof.bin",
           "filename":"proof.bin","content_type":"application/octet-stream"}]}
```

Файлы берутся только из workspace задачи, максимум 16 файлов и 8 MiB суммарного
тела. Boundary детерминирован по данным: новый multipart boundary не позволяет
обойти защиту от повторного POST. Изменение файла означает другие входные байты.

`session_id` именует отдельную сессию текущей задачи (1–64 символа). Cookies и
`auth={"type":"basic","username":"student","password":"candidate"}` либо
`auth={"type":"bearer","token":"candidate"}` сохраняются в приватном material,
SQLite хранит проверяемую ссылку и версию. Authorization привязан к origin,
cookies — к своей сессии/domain/path/secure/expiry. Явные cookies задаются полем
`cookies`, не конкурирующим сырым Cookie-заголовком. Поддержан Set-Cookie и
удаление по сроку/Max-Age. Это HTTP cookie jar, не браузер: JavaScript, OIDC/NTLM,
интерактивный браузер и полная browser SameSite/public-suffix policy не заявлены.

Один незавершённый обмен резервирует веб-сессию. При аварийном обрыве запись
сама по себе не разрешает повторить действие. Новая сессия не предоставляет
новые права/сеть. HTTP-сессия не является живым SSH/PTY-подключением.

## Исходы, повторы, редиректы

`transport_complete` показывает полноту транспорта, `status_code` — HTTP-код.
HTTP 200, 403, отсутствие исключения и запись cookies сами не подтверждают вход,
принятие пароля, доступ или цель. `server_outcome` остаётся uninterpreted для
последующего анализа, проверок доказательств и ответа оператора о флаге.

Память различает method/resource/реальные headers/body и их веб-сессию. Прочтение старого
обмена — local read, не новое наблюдение. Явный свежий GET/HEAD/OPTIONS не берётся
из URL-кэша. Повтор записи с теми же условиями блокируется; timeout/unknown
блокирует повтор независимо от read/fresh. Новые cookies/auth/байты учитываются
как изменившиеся условия; одна новая формулировка не меняет операцию. Переименование
сессии или увеличение лимита ответа не разрешает второй одинаковый POST.

301/302 POST и 303 переходят в GET; 307/308 сохраняют метод/тело. Каждый переход
проверяется PM и root broker до подключения. При смене origin не копируются
исходные Authorization/Cookie и произвольные секретные заголовки. Авторизация
выбирается для нового origin, cookies — заново по domain/path/secure/expiry своей
сессии (как обычно, cookies не разделяются по TCP-порту). Разрешённая загрузка
страницы не разрешает исследовать весь CDN/общий IP. Наружный редирект сохраняется
как ответ приложения и `redirect_outside_scope`, назначение не посещается.

Не более шести hop на один вызов. Все реальные hop расходуют прежний общий
HTTP-бюджет задачи (24 попытки вместе с discovery), а не скрытый отдельный бюджет.
Каждый имеет свой exchange_id, родителя, время, ресурс и сессию. Предыдущие
результаты/статусы задач не переписываются. Повтор модели не повторяет запрос.

## Scope, пути и SSRF

Общего запрета `logout/delete/reset` или traversal по имени больше нет. Явная
граница пути и исключения комнаты проверяют также decoded/normalized варианты;
`/app/../private` не расширяет grant `/app`. Управляющие символы остаются
запрещёнными. Изменяющие запросы к распознаваемым password-change endpoints и
new-password поля JSON/form/multipart/query блокируются; чтение формы изменения
пароля и обычный login password не запрещены. Это bounded
guard поддержанных операций, не полное понимание семантики произвольного API.
Запрет смены паролей и условия комнаты остаются обязательными для агента.

```json
{"url":"http://app.lab:8080/fetch","method":"POST",
 "ssrf":{"destination":"http://127.0.0.1:8081/private",
         "location":"form","parameter":"url","context":"task:11:machine"}}
```

SSRF поддерживает query/form/json параметр. Приложение, точное назначение либо
разрешённая lab-сеть и target-machine context проверяются отдельно; loopback
цели не является loopback Kali. Параметр вставляется компонентом, неоднозначные
дубликаты отклоняются. Сохраняется цепочка application request → declared
destination → observed application response. Намерение/ответ приложения не
объявляются доказательством контакта внутреннего назначения. Это не анализатор
любого payload: произвольный HTTP-текст не становится универсальным SSRF-grant.

## Хранилище и транспорт

`pm_http_exchanges` хранит намерение/запуск/finished/unknown, session/resource/time,
идентичность запроса и связи с оригиналами. `pm_http_sessions` хранит версию и
приватную ссылку на cookie/auth state. Миграция добавочная. Общая память получает
все обмены и версии сессий без сырых credentials и без новых модельных вызовов.

Исходные plaintext HTTP request/response (включая chunk framing/trailers) лежат
в приватных SHA256-addressed `.http` файлах прежнего artifact store, entity body —
в прежнем `.body` и pm_http_artifacts. Raw request ref также участвует в отбраковке
отражённого флага из тела/headers/cookies. Разные методы/inputs не объединяются
в одно свидетельство из-за одинакового URL/ответа. Операторское подтверждение
флага остаётся отдельным прежним механизмом.

`pm_http_read(...,part="request"|"response"|"body",offset=0,limit=4096)` возвращает
проверенный range/base64/hash/has_more. По умолчанию модель видит ≤4096 символов,
с `stdout_truncated`, `text_characters` и отдельными decode flags. Заголовки не
вываливаются в диагностическую консоль; Authorization/cookies не попадают в argv.

Реальный Python HTTP/1.1 worker принимает суммарные headers до **1 MiB**, включая
informational responses и trailers; стандартные 64 KiB/100 fields и меньший
лимит curl не используются в этом пути. Тела ограничены прежней политикой 2/8 MiB,
сырые wire bytes — тем же пределом + headers + 64 KiB framing. Превышение framing,
body/header limit, EOF/timeout/partial помечаются явно. Все материалы учитываются
в 64 MiB artifact budget задачи. Полные допустимые тела сохраняются отдельно от
модельной выдачи; decompression/декодирование имеют свои ограничения.

Рабочий worker запускается фиксированным root-owned broker как task user в
NetGuard namespace/bubblewrap. Сам worker от root не запускается. Каждый hop
проверяет scope/egress/firewall. Прокси из окружения, shell и writable project
imports от root не используются; модельный API сохраняет штатный канал Kali.
TLS проверяется по умолчанию; явный `tls_verify=false` сохраняется в параметрах.
Нужен update установленного broker до `http_protocol=1/http_header_limit=1048576`;
старый broker отклоняется до объявления сетевого запуска. При разработке
установленный broker не менялся, зависимости Harness тоже.

## Проверки и ограничения

[test_http_client_runtime.py](../tests/test_http_client_runtime.py) использует
настоящие локальные HTTP-серверы, настоящий непривилегированный Python worker,
MCP-регистрацию, временную SQLite и artifact store. Подменена только граница
привилегированного broker: логический test-address отображён на реальный loopback
вместо настройки namespace/VPN. Ответы HTTP и сохранение не подменяются.

Проверены POST/query/forms/cookies/multipart, свежий ответ прежнего URL,
origin isolation/редиректы, headers ровно 1 MiB и превышение, chunk framing,
partial body, typed SSRF через локальное приложение (query/form/JSON), защита
password changes и неизвестного POST, отсутствие credential dumps и отражённые
флаги. Это не испытание реального VPN/kernel/bubblewrap, внешнего HTTPS/SNI,
живого приложения, платного API, браузерных/HTTP2/HTTP3 и произвольных SSRF-цепочек.

Итоговый `.venv/bin/python tests/run_offline.py --runtime`: 668 unittest и шесть
legacy-скриптов, ноль сбоев и пропусков. Новый HTTP-набор содержит 24 сценария.
Обе самопроверки, compileall, Node syntax, environment check и `git diff --check`
проходят. Ручные API/инфраструктурные эксперименты не запускались. Рабочие задачи,
SQLite, отчёты и доказательства при разработке не изменялись.
