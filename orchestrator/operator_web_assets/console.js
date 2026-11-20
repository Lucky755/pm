"use strict";

const workspace = document.querySelector("#workspace");
const task = Number(workspace.dataset.task);
const byId = id => document.getElementById(id);

function element(tag, className, parent) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (parent) parent.append(item);
    return item;
}

function write(node, value) {
    const text = String(value ?? "");
    if (node.textContent !== text) node.textContent = text;
}

function patchList(parent, existing, rows, create, update) {
    const ids = new Set(rows.map(row => row.id));
    for (const [id, item] of existing) {
        if (!ids.has(id)) {
            item.remove();
            existing.delete(id);
        }
    }
    for (const row of rows) {
        if (!existing.has(row.id)) existing.set(row.id, create(parent, row));
        update(existing.get(row.id), row);
    }
}

function facts(list, values) {
    if (!list.fields) list.fields = new Map();
    const rows = Object.entries(values).filter(([, value]) => value !== "").map(([label, value]) => ({ id: label, value }));
    patchList(list, list.fields, rows, (parent, row) => {
        const item = element("div", "", parent);
        write(element("dt", "", item), row.id);
        element("dd", "", item);
        return item;
    }, (item, row) => write(item.lastChild, row.value));
}

const panels = { agents: byId("agents"), map: byId("map"), history: byId("history") };
const tabLinks = workspace.querySelectorAll(".tabs a");
const selections = new Map();
const selection = byId("selection");
const selectedTitle = element("h3", "", selection);
const selectedFacts = element("dl", "facts", selection);
let view = "agents";
let recent = null;

function updateSelection() {
    const selected = selections.get(view);
    selection.hidden = !selected;
    byId("selection-hint").hidden = Boolean(selected);
    if (selected) {
        write(selectedTitle, selected.title);
        facts(selectedFacts, selected.details);
    }
}

function setView(name, changeHash = false) {
    view = name;
    for (const [key, panel] of Object.entries(panels)) panel.hidden = key !== view;
    for (const link of tabLinks) {
        if (link.hash === "#" + view) link.setAttribute("aria-current", "page");
        else link.removeAttribute("aria-current");
    }
    if (changeHash) window.history.replaceState(null, "", "#" + view);
    updateSelection();
    if (diagrams[view]) diagrams[view].draw();
    if (view === "history" && !historyStarted && recent) {
        scrollBox.scrollTop = scrollBox.scrollHeight;
        historyStarted = true;
    }
}

const svgNamespace = "http://www.w3.org/2000/svg";
function svgElement(tag, attributes, parent) {
    const node = document.createElementNS(svgNamespace, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
    if (parent) parent.append(node);
    return node;
}

class Diagram {
    constructor(name) {
        this.name = name;
        this.canvas = panels[name].querySelector(".canvas");
        this.columns = new Map(Array.from(this.canvas.querySelectorAll("[data-column]"), el => [el.dataset.column, el]));
        this.cards = new Map();
        this.edges = new Map();
        this.inventory = new Map();
        this.svg = svgElement("svg", { class: "edges", "aria-hidden": "true" }, this.canvas);
        const defs = svgElement("defs", {}, this.svg);
        for (const kind of ["confirmed", "pending", "inactive"]) {
            const marker = svgElement("marker", { id: name + "-" + kind, class: "arrow-" + kind, refX: 8, refY: 5,
                markerWidth: 9, markerHeight: 9, viewBox: "0 0 10 10", orient: "auto", markerUnits: "userSpaceOnUse" }, defs);
            svgElement("path", { d: "M0 0 L10 5 L0 10 Z" }, marker);
        }
        const observer = new ResizeObserver(() => this.draw());
        observer.observe(this.canvas);
    }

    createCard(row) {
        const card = element("article", "diagram-card arriving", this.columns.get(row.column));
        card.dataset.key = row.id;
        const button = element("button", "card-button", card);
        button.type = "button";
        button.setAttribute("aria-pressed", "false");
        element("span", "card-note", button);
        element("strong", "card-title", button);
        element("span", "card-status", button);
        button.addEventListener("click", () => this.select(card));
        if (row.column === "target") {
            this.inventoryList = element("ul", "inventory", card);
            this.inventory.clear();
        }
        return card;
    }

    select(card) {
        const previous = selections.get(this.name);
        if (previous && previous.button) previous.button.setAttribute("aria-pressed", "false");
        const button = card.firstChild;
        button.setAttribute("aria-pressed", "true");
        selections.set(this.name, { id: card.dataset.key, title: card.row.title, details: card.row.details, button });
        updateSelection();
    }

    patch(graph) {
        const visible = new Set(graph.nodes.map(node => node.id));
        const edges = graph.edges.filter(edge => visible.has(edge.from) && visible.has(edge.to));
        patchList(null, this.cards, graph.nodes, (_, row) => this.createCard(row), (card, row) => {
            card.row = row;
            const fields = card.firstChild.children;
            write(fields[0], row.note);
            write(fields[1], row.title);
            write(fields[2], row.status);
            fields[2].hidden = !row.status;
        });
        if (this.inventoryList) {
            patchList(this.inventoryList, this.inventory, graph.inventory, parent => {
                const row = element("li", "arriving", parent);
                element("strong", "", row);
                element("span", "", row);
                return row;
            }, (item, row) => {
                write(item.firstChild, row.label);
                write(item.lastChild, row.value);
            });
        }
        patchList(this.svg, this.edges, edges, parent => {
            const group = svgElement("g", { class: "arriving" }, parent);
            svgElement("path", { class: "wire" }, group);
            svgElement("path", { class: "pulse" }, group);
            const hit = svgElement("path", { class: "edge-select" }, group);
            hit.addEventListener("click", () => this.select(this.cards.get(group.edge.to)));
            return group;
        }, (group, edge) => {
            group.edge = edge;
            const kind = "arriving " + edge.kind;
            if (group.getAttribute("class") !== kind) group.setAttribute("class", kind);
            const marker = "url(#" + this.name + "-" + edge.kind + ")";
            if (group.firstChild.getAttribute("marker-end") !== marker) {
                group.firstChild.setAttribute("marker-end", marker);
            }
        });
        const selected = selections.get(this.name);
        if (selected) {
            const card = this.cards.get(selected.id);
            if (card) {
                selected.title = card.row.title;
                selected.details = card.row.details;
            } else selections.delete(this.name);
        }
        this.draw();
    }

    draw() {
        if (panels[this.name].hidden) return;
        const rect = this.canvas.getBoundingClientRect();
        for (const group of this.edges.values()) {
            const a = this.cards.get(group.edge.from).getBoundingClientRect();
            const b = this.cards.get(group.edge.to).getBoundingClientRect();
            const x = a.right - rect.left;
            const y = a.top + a.height / 2 - rect.top;
            const end = b.left - rect.left - 3;
            const ey = b.top + b.height / 2 - rect.top;
            const mid = (x + end) / 2;
            const d = `M ${x} ${y} C ${mid} ${y}, ${mid} ${ey}, ${end} ${ey}`;
            for (const line of group.children) {
                if (line.getAttribute("d") !== d) line.setAttribute("d", d);
            }
        }
    }
}

const diagrams = { agents: new Diagram("agents"), map: new Diagram("map") };

for (const link of tabLinks) {
    link.addEventListener("click", event => {
        event.preventDefault();
        setView(link.hash.slice(1), true);
    });
}
window.addEventListener("hashchange", () => setView(Object.hasOwn(panels, location.hash.slice(1)) ?
    location.hash.slice(1) : "agents"));

const list = byId("history-entries");
const scrollBox = byId("history-log");
const historyRows = new Map();
const dateFormat = new Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "medium" });
let historyStarted = false;

function createHistoryItem() {
    const item = element("li", "history-item arriving");
    const details = element("details", "", item);
    const summary = element("summary", "", details);
    summary.addEventListener("click", () => selectHistoryItem(item));
    const top = element("span", "entry-meta", summary);
    const time = element("time", "", top);
    const actor = element("span", "", top);
    const origin = element("span", "", top);
    const action = element("strong", "", summary);
    const outcome = element("span", "entry-result", summary);
    const content = element("div", "entry-detail", details);
    const recorded = element("pre", "command", content);
    const factsList = element("dl", "facts", content);
    item.parts = { details, time, actor, origin, action, outcome, recorded, factsList };
    return item;
}

function selectHistoryItem(item) {
    const row = item.row;
    const details = { "Исполнитель": row.actor };
    if (row.details["Сессия"]) details["Сессия"] = row.details["Сессия"];
    selections.set("history", { id: row.id, title: row.action,
        details: { ...details, "Результат": row.result, "Источник": row.source } });
    updateSelection();
}

function patchHistory(rows) {
    const top = scrollBox.getBoundingClientRect().top;
    const anchor = scrollBox.clientHeight && [...list.children].find(el => el.getBoundingClientRect().bottom > top);
    const anchorTop = anchor && anchor.getBoundingClientRect().top;
    const readingEarlier = Array.from(historyRows.values()).some(item => item !== recent && item.parts.details.open);
    const follow = !historyStarted || (!readingEarlier && scrollBox.clientHeight &&
        scrollBox.scrollHeight - scrollBox.clientHeight - scrollBox.scrollTop < 12);
    for (const row of rows) {
        if (!historyRows.has(row.id)) historyRows.set(row.id, createHistoryItem());
        const item = historyRows.get(row.id);
        if (item.record === JSON.stringify(row)) continue;
        item.record = JSON.stringify(row);
        item.row = row;
        const parts = item.parts;
        parts.time.dateTime = row.date;
        write(parts.time, dateFormat.format(new Date(row.date)));
        write(parts.actor, row.kind === "http.exchange" && row.actor === "Не записан" ?
            "Исполнитель не записан" : row.actor);
        write(parts.origin, row.source);
        write(parts.action, row.action);
        write(parts.outcome, row.result);
        write(parts.recorded, row.recorded || "Сохранён только тип операции.");
        facts(parts.factsList, { "Тип события": row.kind, ...row.details });
        if (selections.get("history")?.id === row.id) selectHistoryItem(item);
    }
    const ordered = [...historyRows.values()].sort((a, b) => a.row.timestamp - b.row.timestamp ||
        (a.row.id < b.row.id ? -1 : 1));
    let expected = list.firstChild;
    for (const item of ordered) {
        if (item === expected) expected = expected.nextSibling;
        else list.insertBefore(item, expected);
    }
    recent = ordered.at(-1);
    write(byId("last-event"), recent ? recent.row.action : "Нет сохранённых событий");
    if (follow) scrollBox.scrollTop = scrollBox.scrollHeight;
    else if (anchor) scrollBox.scrollTop += anchor.getBoundingClientRect().top - anchorTop;
    historyStarted ||= Boolean(scrollBox.clientHeight && recent);
}

function showLatest(event) {
    event.preventDefault();
    setView("history", true);
    if (recent) {
        recent.parts.details.open = true;
        selectHistoryItem(recent);
        scrollBox.scrollTop = scrollBox.scrollHeight;
        recent.parts.details.querySelector("summary").focus({ preventScroll: true });
    }
}
byId("history-latest").addEventListener("click", showLatest);
byId("last-event").addEventListener("click", showLatest);

const questions = byId("question-rows");
const questionRows = new Map(Array.from(questions.children, row => [row.dataset.question, row]));
const questionFields = ["title", "text", "reason", "scope"];

function patchQuestions(rows, state) {
    const messages = { missing: "Источник данных отсутствует.", empty: "Ожидающих вопросов нет.",
        error: "Ошибка чтения сохранённых данных." };
    const info = byId("questions-info");
    info.hidden = !messages[state];
    write(info, messages[state]);
    if (state === "error") return;
    patchList(questions, questionRows, rows, (parent, row) => {
        const item = element("li", "arriving", parent);
        item.dataset.question = row.id;
        for (const field of questionFields) {
            element(field === "title" ? "span" : "p", "", item).setAttribute("data-question-" + field, "");
        }
        return item;
    }, (item, row) => {
        const values = { title: "#" + row.id + " · " + row.kind, text: row.question, reason: row.reason, scope: row.scope };
        for (const field of questionFields) {
            write(item.querySelector("[data-question-" + field + "]"), values[field]);
        }
    });
}

function refreshState(snapshot) {
    const goal = byId("goal-outcome");
    if (snapshot.outcome) write(goal, snapshot.outcome);
    if (!snapshot.agents_error) diagrams.agents.patch(snapshot.agents);
    const agentMessage = snapshot.agents_error ? "Не удалось прочитать сохранённые шаги." :
        snapshot.agents.nodes.length ? "" : "Сохранённых координированных шагов нет.";
    write(byId("agent-info"), agentMessage);
    if (snapshot.map) diagrams.map.patch(snapshot.map);
    byId("map-info").hidden = snapshot.map_state !== "error";
    write(byId("map-info"), "Не удалось прочитать сохранённый маршрут.");
    patchHistory(snapshot.history);
    patchQuestions(snapshot.questions, snapshot.questions_state);
    write(byId("history-info"), snapshot.history_error ?
        "Часть источников истории недоступна." :
        "История включает только сохранённые записи PM.");
    updateSelection();
}

async function readState() {
    try {
        const response = await fetch(`/tasks/${task}/view.json`, { cache: "no-store", signal: AbortSignal.timeout(5000) });
        if (!response.ok) throw new Error("Read failed");
        const snapshot = await response.json();
        if (snapshot.task !== task) throw new Error("Wrong task");
        refreshState(snapshot);
        write(byId("connection"), "Чтение сохранённых данных");
    } catch {
        write(byId("connection"), "Источник временно недоступен. Повтор чтения…");
    }
}

async function poll() {
    await readState();
    window.setTimeout(poll, document.hidden ? 8000 : 1500);
}

setView(Object.hasOwn(panels, location.hash.slice(1)) ? location.hash.slice(1) : "agents");
poll();
