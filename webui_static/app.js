"use strict";

/* Hutbot — Watch Desk. Vanilla JS, no build, no external deps.
   Talks to the same-origin API; the bot resolves the proxy header to a user. */

// ---------- tiny DOM helper ----------
function h(tag, attrs, ...kids) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else if (k === "value") node.value = v;
      else if (k === "checked" || k === "disabled" || k === "selected" || k === "hidden") node[k] = !!v;
      else node.setAttribute(k, v);
    }
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return node;
}
const $ = (sel, root = document) => root.querySelector(sel);

// ---------- branding ----------
// Instances (prod / dev) run under different names; /api/meta carries the live one.
let botName = "Hutbot";

function applyBranding(name) {
  if (!name) return;
  botName = name;
  document.title = `${name} · Watch Desk`;
  const brand = $(".brand-name");
  if (brand) brand.textContent = name.toLowerCase();
}

// ---------- state ----------
const state = {
  meta: null,
  channels: [],
  channelId: null,
  configs: {},   // name -> server config (source of truth)
  drafts: {},    // name -> editable copy
  openName: null,
  errors: {},    // name -> { field: message }
};

// ---------- labels ----------
const TRIGGER_LABEL = { message: "Message (classic)", cron: "Cron schedule", manual: "Manual" };
const TRIGGER_SHORT = { message: "message", cron: "cron", manual: "manual" };
const ACTION_LABEL = { reply: "Reply in thread", dm_user: "Direct message", group_dm: "Group DM", post_channel: "Post to channel" };
const ACTION_SHORT = { reply: "reply", dm_user: "dm", group_dm: "group dm", post_channel: "post" };
const CONDITION_LABEL = { "": "None (always)", outlook_calendar: "Outlook calendar" };
const BTN_ACTION_LABEL = { config: "Run rule", ack: "Acknowledge / post text", delay: "Delay timer" };
const ESCALATION_LABEL = { none: "Never escalate; buttons stay open", button: "Auto-press a button", config: "Run another rule" };
const TARGET_HINT = { dm_user: "A @user (id, name, or email)", group_dm: "A @usergroup handle", post_channel: "A channel ID like C0123ABCD" };
// Set by the bot itself when it is removed from a channel (see DISABLED_REASON_REMOVED).
const DISABLED_REASON_LABEL = { removed_from_channel: "Disabled — the bot was removed from this channel" };

// ---------- api ----------
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

// ---------- toasts ----------
function toast(message, isError = false) {
  const node = h("div", { class: "toast" + (isError ? " error" : "") }, h("span", { class: "dot" }), h("span", { text: message }));
  $("#toasts").append(node);
  setTimeout(() => { node.style.opacity = "0"; node.style.transition = "opacity 300ms ease"; setTimeout(() => node.remove(), 320); }, isError ? 6000 : 3200);
}

// ---------- boot ----------
async function boot() {
  const me = await api("GET", "/api/me");
  if (me.status === 403) return fatal("You're signed in, but we couldn't match you to a Slack account. Ask an admin to check your Slack ↔ directory mapping.");
  if (!me.ok) return fatal(`Couldn't reach ${botName}. Try reloading in a moment.`);

  const [meta, channels] = await Promise.all([api("GET", "/api/meta"), api("GET", "/api/channels")]);
  if (!meta.ok || !channels.ok) return fatal("Couldn't load your configuration. Try reloading in a moment.");

  state.meta = meta.data;
  applyBranding(state.meta.bot_name);
  state.channels = channels.data.channels || [];
  document.getElementById("app").setAttribute("aria-busy", "false");
  renderIdentity(me.data);
  renderChannels();

  if (state.channels.length) selectChannel(state.channels[0].id);
  else renderEmptyStage();
}

function fatal(message) {
  $("#stage").replaceChildren(h("div", { class: "stage-empty" }, h("strong", { text: "Can't load the watch desk" }), message));
  document.getElementById("app").setAttribute("aria-busy", "false");
}

// ---------- rail ----------
function initials(name) {
  const parts = (name || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  return (parts[0][0] + (parts[1] ? parts[1][0] : "")).toUpperCase();
}

function renderIdentity(me) {
  const box = $("#identity");
  box.hidden = false;
  $("#identity-avatar").textContent = initials(me.real_name || me.name);
  $("#identity-name").textContent = me.real_name || me.name || me.email;
  const team = me.team && me.team !== "<unknown>" ? me.team : "";
  $("#identity-meta").textContent = [team, me.email].filter(Boolean).join(" · ");
}

function renderChannels() {
  const nav = $("#channels");
  nav.replaceChildren(h("div", { class: "channels-eyebrow", text: "Your channels" }));
  if (!state.channels.length) { nav.append(h("div", { class: "rail-empty", text: "No channels yet." })); return; }
  for (const ch of state.channels) {
    nav.append(h("button", {
      class: "channel-btn",
      "aria-current": ch.id === state.channelId ? "true" : "false",
      onclick: () => selectChannel(ch.id),
    }, h("span", { class: "channel-hash", text: "#" }), h("span", { text: ch.name })));
  }
}

// ---------- stage ----------
function renderEmptyStage() {
  $("#stage").replaceChildren(h("div", { class: "stage-empty" },
    h("strong", { text: "Nothing to watch yet" }),
    `You can manage a channel here once ${botName} has a configuration in it and you're a member.`));
}

async function selectChannel(channelId) {
  state.channelId = channelId;
  state.openName = null;
  state.errors = {};
  renderChannels();
  const stage = $("#stage");
  stage.replaceChildren(h("div", { class: "stage-loading", text: "Loading rules…" }));

  const res = await api("GET", `/api/channels/${encodeURIComponent(channelId)}/configs`);
  if (state.channelId !== channelId) return;
  if (!res.ok) { stage.replaceChildren(h("div", { class: "stage-empty" }, h("strong", { text: "Couldn't load this channel" }), res.data?.error || "Try another channel.")); return; }
  state.configs = res.data.configs || {};
  state.drafts = {};
  renderRules();
}

function channelName() {
  const ch = state.channels.find((c) => c.id === state.channelId);
  return ch ? ch.name : state.channelId;
}

function sortedNames() {
  return Object.keys(state.configs).sort((a, b) => {
    if (a === state.meta.default_config_name) return -1;
    if (b === state.meta.default_config_name) return 1;
    return a.localeCompare(b);
  });
}

function renderRules() {
  const stage = $("#stage");
  const head = h("div", { class: "stage-head" },
    h("div", {}, h("div", { class: "stage-eyebrow", text: "Channel" }),
      h("h1", { class: "stage-title" }, h("span", { class: "hash", text: "#" }), channelName())),
    h("div", { id: "newrule-slot" }, newRuleButton()));
  const rules = h("div", { class: "rules", id: "rules" });
  for (const name of sortedNames()) rules.append(renderCard(name));
  stage.replaceChildren(head, rules);
}

function newRuleButton() {
  return h("button", { class: "btn-newrule", onclick: openNewRuleForm }, h("span", { text: "+" }), "New rule");
}

function openNewRuleForm() {
  const slot = $("#newrule-slot");
  const input = h("input", { type: "text", placeholder: "rule-name", "aria-label": "New rule name" });
  const submit = async () => {
    const name = input.value.trim();
    if (!name) return;
    const res = await api("POST", `/api/channels/${encodeURIComponent(state.channelId)}/configs`, { name });
    if (!res.ok) return toast(res.data?.error || "Couldn't create that rule.", true);
    state.configs[name] = res.data.config;
    state.openName = name;
    renderRules();
    toast(`Created rule “${name}”.`);
  };
  const form = h("div", { class: "newrule-form" }, input,
    h("button", { class: "btn primary", onclick: submit }, "Create"),
    h("button", { class: "btn ghost", onclick: () => slot.replaceChildren(newRuleButton()) }, "Cancel"));
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); if (e.key === "Escape") slot.replaceChildren(newRuleButton()); });
  slot.replaceChildren(form);
  input.focus();
}

// ---------- card (collapsed header + body) ----------
function renderCard(name) {
  const cfg = state.configs[name];
  const isOpen = state.openName === name;
  const card = h("div", { class: "card" + (isOpen ? " open" : "") + (cfg.enabled ? "" : " dim"), "data-name": name });

  const head = h("button", { class: "card-head", onclick: () => toggleCard(name) },
    lampFor(cfg), cardIdBlock(name, cfg), pipelineFor(cfg), tagsFor(cfg),
    h("span", { class: "card-chevron", "aria-hidden": "true", text: "⌄" }));

  const bodyInner = h("div", { class: "card-body-inner" });
  if (isOpen) bodyInner.append(renderEditor(name));
  const body = h("div", { class: "card-body-wrap" }, h("div", { class: "card-body" }, bodyInner));
  card.append(head, body);
  return card;
}

function lampFor(cfg) {
  let cls = "lamp";
  if (!cfg.enabled) cls += " off";
  else if (cfg.opsgenie || cfg.escalation_timeout > 0) cls += " escalating";
  const title = !cfg.enabled
    ? (DISABLED_REASON_LABEL[cfg.disabled_reason] || "Disabled")
    : (cfg.opsgenie || cfg.escalation_timeout > 0) ? "Active · can escalate" : "Active";
  return h("span", { class: cls, title, role: "img", "aria-label": title });
}

function cardIdBlock(name, cfg) {
  const nameNode = h("span", { class: "card-name", text: name });
  if (name === state.meta.default_config_name) nameNode.append(h("span", { class: "default-tag", text: "default" }));
  return h("span", { class: "card-id" }, nameNode);
}

function pipelineFor(cfg) {
  const condText = cfg.trigger === "cron" && cfg.condition === "outlook_calendar"
    ? (cfg.condition_negate ? "no outlook" : "outlook") : "—";
  const chip = (kind, text, muted) => h("span", { class: "pipe-chip" + (muted ? " muted" : "") },
    h("span", { class: "pipe-kind", text: kind }), text);
  return h("span", { class: "pipeline" },
    chip("on", TRIGGER_SHORT[cfg.trigger] || cfg.trigger),
    h("span", { class: "pipe-sep", text: "›" }),
    chip("when", condText, condText === "—"),
    h("span", { class: "pipe-sep", text: "›" }),
    chip("do", ACTION_SHORT[cfg.action] || cfg.action));
}

function tagsFor(cfg) {
  const tags = h("span", { class: "card-tags" });
  if (!cfg.enabled) tags.append(h("span", { class: "tag off", text: "off" }));
  const btnCount = (cfg.buttons || []).length;
  if (btnCount) tags.append(h("span", { class: "tag", text: btnCount === 1 ? "1 button" : `${btnCount} buttons` }));
  if (cfg.opsgenie) tags.append(h("span", { class: "tag opsgenie", text: `OpsGenie ${cfg.opsgenie_priority || ""}`.trim() }));
  return tags;
}

function toggleCard(name) {
  if (state.openName === name) { state.openName = null; renderRules(); return; }
  state.openName = name;
  state.errors[name] = {};
  state.drafts[name] = JSON.parse(JSON.stringify(state.configs[name]));
  renderRules();
}

// ---------- editor ----------
function draft() { return state.drafts[state.openName]; }
function errs() { return state.errors[state.openName] || {}; }
function isDirty(name) { return JSON.stringify(state.drafts[name]) !== JSON.stringify(state.configs[name]); }

function set(field, value) { draft()[field] = value; liveRefresh(); }

function liveRefresh() {
  // Update the collapsed header (lamp/pipeline/tags) and the apply bar without
  // disturbing focus in text inputs.
  const name = state.openName;
  const card = $(`.card[data-name="${cssEscape(name)}"]`);
  if (!card) return;
  const cfg = state.drafts[name];
  card.classList.toggle("dim", !cfg.enabled);
  // Replace only the header's children — the .card-head button keeps its
  // original click handler from renderCard, so we must not re-bind here.
  $(".card-head", card).replaceChildren(
    lampFor(cfg), cardIdBlock(name, cfg), pipelineFor(cfg), tagsFor(cfg),
    h("span", { class: "card-chevron", "aria-hidden": "true", text: "⌄" }));
  refreshApplyBar();
}

function structuralRefresh() {
  const card = $(`.card[data-name="${cssEscape(state.openName)}"]`);
  if (card) $(".card-body-inner", card).replaceChildren(renderEditor(state.openName));
  liveRefresh();
}

function cssEscape(s) { return (window.CSS && CSS.escape) ? CSS.escape(s) : s.replace(/["\\]/g, "\\$&"); }

function fieldErr(field) { return errs()[field]; }

// section + field builders -------------------------------------------------
function section(title, badge, ...rows) {
  const t = h("div", { class: "section-title" }, title);
  if (badge) t.append(h("span", { class: "badge", text: badge }));
  return h("div", { class: "section" }, t, ...rows);
}
function grid(...fields) { return h("div", { class: "grid" }, ...fields); }

function field(labelText, control, { hint, error, wide } = {}) {
  const f = h("div", { class: "field" + (wide ? " wide" : "") }, h("label", { class: "field-label", text: labelText }), control);
  if (hint) f.append(h("div", { class: "hint", text: hint }));
  if (error) f.append(h("div", { class: "err", text: error }));
  if (error && control.classList) control.classList.add("invalid");
  return f;
}

function textInput(field_, { mono, placeholder } = {}) {
  return h("input", { type: "text", class: mono ? "mono" : "", value: draft()[field_] ?? "", placeholder: placeholder || "",
    oninput: (e) => set(field_, e.target.value) });
}
function selectInput(field_, options, labels, onAfter) {
  const sel = h("select", { onchange: (e) => { draft()[field_] = e.target.value; (onAfter || liveRefresh)(); } });
  for (const opt of options) sel.append(h("option", { value: opt, selected: draft()[field_] === opt }, labels ? (labels[opt] ?? opt) : opt));
  return sel;
}
function toggleInput(field_, text, { amber, onAfter } = {}) {
  const input = h("input", { type: "checkbox", checked: !!draft()[field_], onchange: (e) => { draft()[field_] = e.target.checked; (onAfter || liveRefresh)(); } });
  return h("label", { class: "toggle" + (amber ? " amber" : "") }, input, h("span", { class: "track" }), h("span", { class: "toggle-text", text }));
}
function minutesInput(field_) {
  const cur = Math.round((draft()[field_] || 0) / 60);
  return h("input", { type: "number", min: "0", max: "1440", value: cur,
    oninput: (e) => { const m = parseInt(e.target.value, 10); draft()[field_] = isNaN(m) ? 0 : m * 60; liveRefresh(); } });
}

function renderEditor(name) {
  const cfg = draft();
  const e = errs();
  const wrap = h("div", {});

  // — Status & trigger —
  const triggerRows = [grid(
    field("This rule is", h("div", {}, toggleInput("enabled", cfg.enabled ? "Active" : "Disabled", { onAfter: () => { liveRefresh(); structuralRefreshLabelOnly(); } })),
      { hint: !cfg.enabled && DISABLED_REASON_LABEL[cfg.disabled_reason] ? "The bot disabled this rule when it was removed from this channel." : "" }),
    field("Trigger", selectInput("trigger", state.meta.triggers, TRIGGER_LABEL, structuralRefresh), { hint: triggerHint(cfg.trigger) }),
  )];
  if (cfg.trigger === "message") {
    triggerRows.push(grid(field("Reminder delay (minutes)", minutesInput("wait_time"),
      { hint: "How long to wait for a reply before nudging.", error: fieldErr("wait_time") })));
  }
  if (cfg.trigger === "cron") {
    triggerRows.push(grid(
      field("Cron schedule", textInput("cron", { mono: true, placeholder: "0 9 * * 1-5" }),
        { hint: "5-field cron, in the Date & time timezone below.", error: fieldErr("cron") }),
    ));
  }
  wrap.append(section("Status & trigger", null, ...triggerRows));

  // — Condition (schedule only) —
  if (cfg.trigger === "cron") {
    const condRows = [grid(field("Condition", selectInput("condition", state.meta.conditions, CONDITION_LABEL, structuralRefresh),
      { hint: "Gate the schedule on an Outlook calendar entry." }))];
    if (cfg.condition === "outlook_calendar") {
      condRows.push(grid(
        field("Subject matches", textInput("outlook_subject_pattern", { mono: true, placeholder: "regex" }), { error: fieldErr("outlook_subject_pattern") }),
        field("Body matches", textInput("outlook_body_pattern", { mono: true, placeholder: "regex" }), { error: fieldErr("outlook_body_pattern") }),
      ));
      condRows.push(h("div", { class: "toggles-row" }, toggleInput("condition_negate", "Fire when no matching entry exists")));
    }
    wrap.append(section("Condition", "cron", ...condRows));
  }

  // — Action —
  const actionRows = [grid(field("Action", selectInput("action", state.meta.actions, ACTION_LABEL, structuralRefresh), { hint: ACTION_LABEL[cfg.action] }))];
  if (cfg.action !== "reply") {
    actionRows[0].append(field("Target", textInput("action_target", { mono: true }), { hint: TARGET_HINT[cfg.action], error: fieldErr("action_target") }));
  }
  wrap.append(section("Action", null, ...actionRows));

  // — Message —
  wrap.append(section("Message", null, messageField()));

  // — Filters (message trigger) —
  if (cfg.trigger === "message") wrap.append(filtersSection());

  // — Buttons —
  wrap.append(buttonsSection());

  // — OpsGenie —
  wrap.append(opsgenieSection());

  // — Formatting (advanced) —
  wrap.append(formattingSection());

  // — Apply bar —
  wrap.append(applyBar(name));
  return wrap;
}

// enabled toggle text needs a relabel without a full structural rebuild
function structuralRefreshLabelOnly() {
  const card = $(`.card[data-name="${cssEscape(state.openName)}"]`);
  if (!card) return;
  const txt = $(".section .toggle .toggle-text", card);
  if (txt) txt.textContent = draft().enabled ? "Active" : "Disabled";
}

function triggerHint(t) {
  if (t === "message") return "Watches channel messages and nudges if unanswered.";
  if (t === "cron") return "Fires on a cron schedule.";
  return "Only runs when a button or another rule calls it.";
}

function messageField() {
  const e = errs();
  const ta = h("textarea", { class: "mono", value: draft().reply_message ?? "", oninput: (ev) => set("reply_message", ev.target.value) });
  if (fieldErr("reply_message")) ta.classList.add("invalid");
  const wrap = h("div", { class: "field wide" }, h("label", { class: "field-label", text: "Message body" }), ta);
  if (fieldErr("reply_message")) wrap.append(h("div", { class: "err", text: fieldErr("reply_message") }));
  else wrap.append(h("div", { class: "hint", text: "Supports {{variables}}. Click a variable to insert it." }));

  const bar = h("div", { class: "varbar" }, h("div", { class: "varbar-label", text: "Insert variable" }));
  const chips = h("div", { class: "chipset" });
  for (const v of state.meta.template_variables) {
    chips.append(h("button", { class: "chip var", type: "button", onclick: () => insertVar(ta, v) }, `{{${v}}}`));
  }
  bar.append(chips);
  wrap.append(bar);
  return wrap;
}

function insertVar(ta, v) {
  const token = `{{${v}}}`;
  const start = ta.selectionStart ?? ta.value.length;
  const end = ta.selectionEnd ?? ta.value.length;
  ta.value = ta.value.slice(0, start) + token + ta.value.slice(end);
  ta.focus();
  ta.selectionStart = ta.selectionEnd = start + token.length;
  set("reply_message", ta.value);
}

function filtersSection() {
  const cfg = draft();
  const rows = [];
  rows.push(grid(
    field("Only react to messages matching", textInput("pattern", { mono: true, placeholder: "regex (blank = all)" }), { error: fieldErr("pattern") }),
    h("div", { class: "field" }, h("label", { class: "field-label", text: "Options" }),
      h("div", { class: "toggles-row" },
        toggleInput("pattern_case_sensitive", "Case-sensitive"),
        toggleInput("include_bots", "Include bot messages"),
        toggleInput("only_work_days", "Weekdays only"))),
  ));

  // work hours
  const hours = Array.isArray(cfg.hours) && cfg.hours.length === 2 ? cfg.hours : ["", ""];
  const startI = h("input", { type: "time", value: hours[0], onchange: (e) => setHours(e.target.value, null) });
  const endI = h("input", { type: "time", value: hours[1], onchange: (e) => setHours(null, e.target.value) });
  const hoursField = h("div", { class: "field" }, h("label", { class: "field-label", text: "Active hours (blank = all day)" }),
    h("div", { class: "hours-row" }, startI, h("span", { class: "hint", text: "to" }), endI));
  if (fieldErr("hours")) hoursField.append(h("div", { class: "err", text: fieldErr("hours") }));

  // team filter
  rows.push(grid(hoursField, teamFilterField()));
  return section("Filters", "message", ...rows);
}

function setHours(start, end) {
  const cfg = draft();
  const cur = Array.isArray(cfg.hours) && cfg.hours.length === 2 ? cfg.hours.slice() : ["", ""];
  if (start !== null) cur[0] = start;
  if (end !== null) cur[1] = end;
  cfg.hours = (cur[0] && cur[1]) ? cur : (!cur[0] && !cur[1] ? [] : cur);
  liveRefresh();
}

function teamFilterField() {
  const cfg = draft();
  const mode = cfg.included_teams.length ? "only" : cfg.excluded_teams.length ? "except" : "all";
  const seg = h("div", { class: "segmented", role: "group", "aria-label": "Team filter" });
  const modes = [["all", "All teams"], ["only", "Only these"], ["except", "Except these"]];
  for (const [m, label] of modes) {
    seg.append(h("button", { type: "button", "aria-pressed": mode === m ? "true" : "false", onclick: () => setTeamMode(m) }, label));
  }
  const f = h("div", { class: "field" }, h("label", { class: "field-label", text: "Team filter" }), seg);
  if (mode !== "all") {
    const active = mode === "only" ? cfg.included_teams : cfg.excluded_teams;
    const chips = h("div", { class: "chipset mt-sm" });
    if (!state.meta.teams.length) chips.append(h("span", { class: "hint", text: "No teams known yet." }));
    for (const team of state.meta.teams) {
      const on = active.includes(team);
      chips.append(h("button", { type: "button", class: "chip", "aria-pressed": on ? "true" : "false", onclick: () => toggleTeam(mode, team) }, team));
    }
    f.append(chips);
  }
  if (fieldErr("included_teams")) f.append(h("div", { class: "err", text: fieldErr("included_teams") }));
  if (fieldErr("excluded_teams")) f.append(h("div", { class: "err", text: fieldErr("excluded_teams") }));
  return f;
}

function setTeamMode(mode) {
  const cfg = draft();
  if (mode === "all") { cfg.included_teams = []; cfg.excluded_teams = []; }
  else if (mode === "only") { cfg.included_teams = cfg.included_teams.length ? cfg.included_teams : cfg.excluded_teams; cfg.excluded_teams = []; }
  else { cfg.excluded_teams = cfg.excluded_teams.length ? cfg.excluded_teams : cfg.included_teams; cfg.included_teams = []; }
  structuralRefresh();
}
function toggleTeam(mode, team) {
  const key = mode === "only" ? "included_teams" : "excluded_teams";
  const list = draft()[key];
  const i = list.indexOf(team);
  if (i >= 0) list.splice(i, 1); else list.push(team);
  structuralRefresh();
}

function buttonsSection() {
  const cfg = draft();
  const rows = h("div", { class: "btn-rows" });
  const buttons = cfg.buttons || [];
  if (!buttons.length) rows.append(h("div", { class: "btn-empty", text: "No buttons. Add one to make this message interactive." }));
  buttons.forEach((btn, i) => rows.append(buttonRow(btn, i)));

  const add = h("button", { class: "add-row", type: "button", onclick: () => { cfg.buttons = buttons.concat([{ label: "", action: "ack", value: "" }]); structuralRefresh(); } }, "+ Add button");

  // Escalation is one setting: minutes + what to escalate to. Picking "Never" hides
  // the rest, so the form cannot produce a timer with nothing to fire.
  const escalationKinds = ["none", "button", "config"];
  const meta = grid(
    field("If nobody presses", selectInput("escalation_kind", escalationKinds, ESCALATION_LABEL, structuralRefresh),
      { hint: ESCALATION_LABEL[cfg.escalation_kind || "none"], error: fieldErr("escalation_kind") }),
  );
  if (cfg.escalation_kind === "button" || cfg.escalation_kind === "config") {
    meta.append(field("After (minutes)", minutesInput("escalation_timeout"), { error: fieldErr("escalation_timeout") }));
    meta.append(field(cfg.escalation_kind === "button" ? "Button to press" : "Rule to run",
      textInput("escalation_target", { mono: cfg.escalation_kind === "config" }),
      { hint: cfg.escalation_kind === "button" ? "A button label above." : "Another rule's name.", error: fieldErr("escalation_target") }));
  }

  return section("Buttons", null, rows, add, meta);
}

function buttonRow(btn, i) {
  const labelI = h("input", { type: "text", value: btn.label || "", placeholder: "Label", oninput: (e) => { btn.label = e.target.value; liveRefresh(); } });
  const actionSel = h("select", { onchange: (e) => { btn.action = e.target.value; structuralRefresh(); } });
  for (const a of state.meta.button_actions) actionSel.append(h("option", { value: a, selected: btn.action === a }, BTN_ACTION_LABEL[a] || a));
  const onValue = (e) => { btn.value = e.target.value; liveRefresh(); };
  let valueControl;
  if (btn.action === "delay") valueControl = h("input", { type: "number", min: "1", max: "1440", value: btn.value || "", placeholder: "Minutes", oninput: onValue });
  else if (btn.action === "config") valueControl = h("input", { type: "text", class: "mono", value: btn.value || "", placeholder: "Rule name", oninput: onValue });
  else valueControl = h("input", { type: "text", value: btn.value || "", placeholder: "Optional message to post", oninput: onValue });
  const remove = h("div", { class: "drop" }, h("button", { class: "icon-btn", type: "button", title: "Remove button", "aria-label": "Remove button", onclick: () => { draft().buttons.splice(i, 1); structuralRefresh(); } }, "×"));
  const row = h("div", { class: "btn-row" }, labelI, actionSel, valueControl, remove);
  if (fieldErr(`buttons.${i}`)) { row.classList.add("has-error"); row.append(h("div", { class: "err row-err", text: fieldErr(`buttons.${i}`) })); }
  return row;
}

function opsgenieSection() {
  const cfg = draft();
  const rows = [h("div", { class: "toggles-row" }, toggleInput("opsgenie", "Page OpsGenie when this rule runs", { amber: true, onAfter: structuralRefresh }))];
  if (cfg.opsgenie) {
    if (!state.meta.opsgenie_configured) rows.push(h("div", { class: "hint opsgenie-warn", text: "OpsGenie isn't configured on the server — alerts won't be delivered until it is." }));
    rows.push(grid(
      field("Schedule name", textInput("opsgenie_schedule_name"), { error: fieldErr("opsgenie_schedule_name") }),
      field("Priority", selectInput("opsgenie_priority", state.meta.opsgenie_priorities, null), {}),
    ));
    const ta = h("textarea", { class: "mono", value: cfg.opsgenie_message ?? "", placeholder: "Blank = the original message", oninput: (e) => set("opsgenie_message", e.target.value) });
    if (fieldErr("opsgenie_message")) ta.classList.add("invalid");
    const msg = h("div", { class: "field wide" }, h("label", { class: "field-label", text: "Alert text" }), ta);
    if (fieldErr("opsgenie_message")) msg.append(h("div", { class: "err", text: fieldErr("opsgenie_message") }));
    else msg.append(h("div", { class: "hint", text: "Supports {{variables}}." }));
    rows.push(msg);
  }
  return section("OpsGenie", cfg.opsgenie ? "escalation" : null, ...rows);
}

function formattingSection() {
  const cfg = draft();
  const body = h("div", { class: "pt-sm" }, grid(
    field("Date format", textInput("date_format", { mono: true, placeholder: "%a, %d %b %Y" })),
    field("Time format", textInput("time_format", { mono: true, placeholder: "%H:%M" })),
    field("Timezone", textInput("datetime_timezone", { mono: true, placeholder: "Europe/Berlin" }), { hint: "IANA name; also counts work days/hours. Blank = server local time.", error: fieldErr("datetime_timezone") }),
    field("Locale", textInput("datetime_locale", { mono: true, placeholder: "de_DE" }), { hint: "Blank = the instance default. Only de has translations.", error: fieldErr("datetime_locale") }),
  ), h("div", { class: "toggles-row mt-md" }, toggleInput("debug", "Verbose debug logging")));
  const details = h("details", { class: "section formatting" }, h("summary", { class: "section-title summary-toggle", text: "Date & time formatting" }), body);
  return details;
}

function applyBar(name) {
  const dirty = isDirty(name);
  const bar = h("div", { class: "applybar", "data-applybar": "1" });
  if (dirty) { bar.append(h("span", { class: "dirty-dot" }), h("span", { class: "status", text: "Unsaved changes" })); }
  else bar.append(h("span", { class: "status", text: "All changes applied" }));
  bar.append(h("span", { class: "spacer" }));
  if (name !== state.meta.default_config_name) {
    bar.append(h("button", { class: "btn danger-text", onclick: () => deleteRule(name) }, "Delete rule"));
  }
  bar.append(h("button", { class: "btn ghost", disabled: !dirty, onclick: () => revertRule(name) }, "Revert"));
  bar.append(h("button", { class: "btn primary", disabled: !dirty, onclick: () => applyRule(name) }, "Apply changes"));
  return bar;
}

function refreshApplyBar() {
  const card = $(`.card[data-name="${cssEscape(state.openName)}"]`);
  if (!card) return;
  const old = $('[data-applybar]', card);
  if (old) old.replaceWith(applyBar(state.openName));
}

function revertRule(name) {
  state.drafts[name] = JSON.parse(JSON.stringify(state.configs[name]));
  state.errors[name] = {};
  structuralRefresh();
  toast("Reverted to the applied configuration.");
}

async function applyRule(name) {
  const res = await api("PUT", `/api/channels/${encodeURIComponent(state.channelId)}/configs/${encodeURIComponent(name)}`, state.drafts[name]);
  if (res.status === 422) {
    state.errors[name] = res.data.errors || {};
    structuralRefresh();
    toast("Some fields need fixing — see the highlights.", true);
    return;
  }
  if (!res.ok) { toast(res.data?.error || "Couldn't apply changes.", true); return; }
  state.configs[name] = res.data.config;
  state.drafts[name] = JSON.parse(JSON.stringify(res.data.config));
  state.errors[name] = {};
  structuralRefresh();
  toast(`Applied “${name}”.`);
}

async function deleteRule(name) {
  if (!window.confirm(`Delete rule “${name}”? This can't be undone.`)) return;
  const res = await api("DELETE", `/api/channels/${encodeURIComponent(state.channelId)}/configs/${encodeURIComponent(name)}`);
  if (!res.ok) { toast(res.data?.error || "Couldn't delete that rule.", true); return; }
  delete state.configs[name];
  delete state.drafts[name];
  state.openName = null;
  renderRules();
  toast(`Deleted “${name}”.`);
}

boot();
