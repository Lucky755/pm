# JavaScript-браузер и Burp Professional

Реализовано от `168ad6e`, 16 ноября 2026. Это дополнительный исполнитель
конкретного веб-поручения, а не новый координатор или расширение разрешений.
Базовый браузер работает без Burp, модельного API и собственного HTTP-кэша PM.

## Браузер

Используются Playwright Python **1.58.0** и установленный Chromium. Здесь
проверен Chromium **156.0.8078.47** (`/usr/lib/chromium/chromium`); другой браузер
не скачивается автоматически. Зависимости Harness не изменены. Оператор после
обновления root-owned broker может явно настроить задачу:

```sh
python3 pm.py browser-config 11 --runtime /home/lucky/pentest-master/.venv --chromium /usr/lib/chromium/chromium
```

Это пример конфигурации, **не выполненная над рабочей задачей команда**.
Требуются `browser_protocol=1`, `http_protocol=1` и поддержка namespace/bubblewrap
из текущего `executor/netguard_root.py`. Старый установленный broker не
подменяется новым при разработке. Отсутствующая конфигурация/бинарник возвращает
недоступность, не фиктивный успешный сеанс.

`pm_browser(task_id, action="open", url, username, purpose)` создаёт отдельный
контекст без навигации. Дальнейшие `action="control", action_json=...`:

```json
{"action":"open","url":"http://app.lab:8080/login?next=%2Faccount#form"}
{"action":"wait","selector":"#login"}
{"action":"fill","selector":"#user","value":"alice"}
{"action":"fill","selector":"#password","value":"candidate"}
{"action":"click","selector":"#submit"}
{"action":"wait","selector":"#account"}
{"action":"read","read_selector":"#account"}
```

Каждый объект — отдельный вызов с сохранённым `session_id`. Выбор профиля
`browser-web` добавляет только соответствующую процедуру/инструменты; лимит
специалиста пересекается с бюджетом задания. Форма, CSRF, JS, cookies,
localStorage/IndexedDB и sessionStorage принадлежат этому браузерному пользователю.
Имя пользователя — назначение сессии, **не доказательство входа**. Другой
пользователь получает другой контекст; cookies неизвестного пользователя Burp
в браузер не импортируются. Нет автоматического переноса HTTP cookie jar.

Общий менеджер сессий хранит ресурс, назначение, владельца и историю; браузер
участвует в общей квоте десяти сессий и межпроцессном lock. Завершение роли
освобождает владение полезным контекстом. После передачи сначала нужно прочитать
состояние. `status/release/close` используют тот же менеджер. Status проверяет
локальный worker/socket, не вход и не полную работоспособность renderer;
живое чтение DOM выполняется явным control/read. После смерти worker
явный `restore` по сохранившейся квитанции открывает пустую страницу с прежним
storage, **не повторяет навигацию/submit**. Явный `close` удаляет квитанцию; это
не восстановление прерванного процесса. Неизвестный исход запрещает повтор;
даже чтение DOM не доказывает, что потерянный submit не выполнился. Автоматического
разрешения такого исхода нет: нужны проверка оператором и сохранённые материалы.

Chromium/Playwright работают как task user в sandbox с пустым network namespace.
Ни Node, ни страница не имеют прямого пути к сети Kali/цели. Поддержанный
Playwright CDPSession/Chromium Fetch.requestPaused
передают реальные запросы root-контроллеру по IPC; существующий HTTP worker
в namespace задачи проверяет текущий resource policy/адрес, Host/SNI, путь,
условия комнаты и запрет смены паролей. Каждый redirect/JS fetch проверяется
отдельно. BrowserContext.route не использован: реальный тест воспроизвёл обход
его callback на redirect. Fetch перехватывает каждый переход, сохраняя final URL
и cookies браузера; эта разница покрыта регрессией. Разрешённая точная page
dependency не даёт права исследовать весь CDN.
Возвращённые реальные HTTP-байты исполняются настоящим Chromium. Service workers
блокируются, WebSockets закрываются; generic evaluate, downloads, uploads через
file chooser, управление popup/отдельными cross-origin worker/OOPIF targets не
предоставлены (неперехваченные обращения не имеют сети). Это явные ограничения, не
попытка незаметно обойти scope другим браузерным транспортом.

Используется общий HTTP-счётчик задачи (24 запроса), максимум 12 секунд ожидания
локатора/HTTP-обмена; UI-вызов ограничен 45/50 секундами broker/frontend.
Ответы для renderer ограничены 2 MiB на тело, 1 MiB на заголовки и 32 MiB
для совокупных материалов UI-действия. После достижения порога новый обмен
не отправляется; уже полученный обмен сохраняется и при превышении порога.
Неполный ответ не выдаётся за полный.
Повтор изменяющего запроса/unknown запрещён root-журналом исполнения; fresh
GET/HEAD/OPTIONS разрешён как явная проверка, без возврата URL-кэша.

`pm_browser_actions`, `pm_browser_network` и существующие `pm_http_exchanges` /
artifact store сохраняют наблюдаемый DOM, запросы/ответы, время, ресурс и сессию.
Каждое захваченное HTTP-сообщение получает оригинальную ссылку `http_artifact:N`
и `network_result_ids` capability log; HTML renderer — отдельный материал
`browser_dom:N`. Текст выдачи ≤6000 символов, сохранённый DOM ≤2 MiB, усечение
помечается. `pm_browser_read`/`pm_material_read` читают сохранённые диапазоны без
worker, сети и нового наблюдения. DOM/снимок экрана, status=completed, HTTP 200
и завершение click не подтверждают доступ/цель. Скриншоты как доказательство
успеха не используются. Диагностика хранит action/run/session IDs и статус,
не значения полей, cookies или полный сетевой поток.

При ошибке импорта материалов после выполненного HTTP возвращаются отдельно
`capture_import_failed` и `execution_outcome`; это не отказ до исполнения.
Каноническое действие остаётся unknown, повтор не запускается автоматически.
Исходные HTTP-сообщения до возврата renderer сохраняются также в приватных
неизменных broker-квитанциях с task/session/time и SHA256 ID. `root_http_receipts`
в ошибке — ссылки на них, не выдуманные capability result_id. Операторский
`browser --action result --receipt-id` читает конкретную квитанцию без сети,
даже после следующего DOM-read/закрытия сессии. Есть проверка task/session/hash;
автоматический импорт после такого сбоя не реализован. Квитанции сохраняются
до явной очистки task broker и требуют места, как другие исходные материалы.

## Burp: фактические интерфейсы и границы

Проверены официальные интерфейсы [Montoya Proxy](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/Proxy.html),
[ProxyHttpRequestResponse](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/ProxyHttpRequestResponse.html)
и [настройка внешнего браузера/Proxy](https://portswigger.net/burp/documentation/desktop/external-browser-config).
Используются `api.proxy().history()` и `registerRequestHandler()`, обычные
HTTP Proxy/CONNECT и CA, а не придуманный vendor REST/MCP для истории.
`/health`, `/history`, `/messages` — **наши** endpoints Java-расширения
`integrations/burp-bridge`, не встроенный API Burp. Старый metadata importer
Evidence Hub сохранён отдельно.

Расширение компилируется с официальным **Montoya 2026.7**, Java **21+**.
В этом окружении Burp не установлен, настоящая Pro-лицензия/версия не проверена.
Health требует `protocol=3`, `edition=PROFESSIONAL`, `guarded_proxy=true` и
сохраняет реальную версию/instance ID. Без этого `burp_unavailable`; основной
браузер остаётся доступным. Автоматического запуска/установки Burp нет.

Для реального использования оператор настраивает **выделенный экземпляр Pro
в network namespace этой задачи** (тот же UID/HOME), loopback Proxy, например
8080, и загружает собранный `pentest-master-burp-bridge.jar`. Bridge слушает
`127.0.0.1:17779` и создаёт приватный `~/.config/pentest-master/burp-bridge.token`.
Intercept должен быть выключен; сторонние расширения/правила изменения,
автоматические сканеры и произвольные session-handling requests не входят в
поддержанную конфигурацию. Не направляйте задачу в обычный host/Kali proxy,
имеющий неограниченный внешний egress. Root-конфигурация задачи получает
`--burp-proxy-port`, `--burp-bridge-port`, при HTTPS — экспортированный
`--burp-ca`. CA проверяется по сохранённому хэшу, TLS не отключается молча.

`proxy="burp"` в browser open или HTTP request выбирает **свежую** отправку
через этот listener. Numeric IP фиксирует адрес, исходный Host/SNI сохраняется.
Broker выдаёт короткую HMAC-квитанцию конкретных method/address/Host/path/body/
auth/cookies; Montoya guard проверяет её перед отправкой, удаляет служебный
заголовок, одноразово потребляет nonce и annotates историю для корреляции.
Запрос без квитанции/с изменёнными параметрами отклоняется. Это не универсальное
разрешение Repeater/Scanner/любому расширению и не обещание безопасности
произвольной пользовательской конфигурации Burp.

`pm_burp(status)` проверяет возможность; `import(url,after,limit)` читает
уже существующую историю, а `read` — только SQLite. Они не обращаются к цели.
Импорт ограничен origin/current address/path, 1–3 сообщения, ≤9 MiB каждый
request/response, ≤32 MiB кодированных данных за страницу. Пропуски oversized,
cursor и наличие продолжения обозначены. ID включает instance ID; повторный
импорт идемпотентен. Полные Montoya HTTP messages сохраняются приватно с хэшами
и материалами `burp:INSTANCE:ID:request|response` в общей памяти. Это сериализация
Montoya, не заявление о точном TLS/TCP wire framing. Пассивный импорт не создаёт
нового сетевого свидетельства. Проксированный capture маркируется отдельно:
байты от изменяемого proxy без корреляции оригинальной истории не повышаются
до технического доказательства цели; ручное подтверждение флага сохраняется.

## Что действительно проверено

- [test_browser_runtime.py](../tests/test_browser_runtime.py): настоящий
  Chromium/Playwright, JavaScript login + два Set-Cookie + CSRF POST, реальные
  TCP/Unix sockets и MCP-регистрация; отдельные пользователи, role handoff,
  запрет внешнего fetch, сохранённое чтение, restore без replay, unknown и
  symlink/одновременное владение, реальное исчерпание временной artifact-квоты
  после исполнения и сохранность квитанции после DOM-read. Только launcher/namespace
  заменён локальным driver; реальные HTTP-ответы и persistence не подменяются.
- [test_burp_adapter.py](../tests/test_burp_adapter.py): контракт публичного MCP,
  broker заменён; unavailable/edition, scope, idempotent passive import,
  оригиналы в памяти и отсутствие send API. **Не живой Burp.**
- [test_burp_proxy_runtime.py](../tests/test_burp_proxy_runtime.py): настоящие
  HTTP proxy и TLS CONNECT/SNI/CA на loopback с локальным proxy-имитатором.
  Публичный MCP-путь сохраняет proxy на redirect; смена транспорта не разрешает
  повтор завершённого POST.
  **Не проверка interception/guard/CA настоящего Burp.**
- [check_burp_java.py](../tests/check_burp_java.py): javac против настоящего
  официального API JAR, Python→Java HMAC/path/one-use contract. Java-тест
  использует dynamic proxies реальных интерфейсов, **не экземпляр Burp**:

```sh
.venv/bin/python tests/check_burp_java.py --montoya-jar /tmp/pm-montoya-api-2026.7.jar
```

Без настоящего JAR команда завершается ошибкой, skip/поддельных API-классов нет.
Сборка `gradle -p integrations/burp-bridge jar` требует доступного Maven artifact.
Проверенные upstream-механизмы Playwright: [storage state](https://playwright.dev/python/docs/auth),
[CDPSession](https://playwright.dev/python/docs/api/class-cdpsession) /
[Chromium Fetch](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/),
[блокировка service workers](https://playwright.dev/python/docs/service-workers).

Не проверены живой Pro, его лицензия/Proxy history/CONNECT interception,
пользовательская настройка CA, установленный root broker/namespace/VPN и
настоящая CTF-цель. Live Burp-приёмка требует отдельного локального экземпляра:
запрос через guard, импорт того же nonce, отклонение изменённого запроса и
запрещённого redirect, затем HTTPS с CA. Неизвестная совместимость не выдаётся
за пройденную интеграцию. Нет OIDC/NTLM/HTTP2/HTTP3, полного browser automation,
parallel coordinator или гарантии статического анализа любого password-change
API. Рабочие задачи/SQLite/отчёты/captures и установленный broker не изменялись.
