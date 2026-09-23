/* prompt-to-mcp UI.
 *
 * Deliberately dependency-free: no bundler, no framework, no CDN. The control
 * plane image stays a plain Python image with no Node build step, and the UI
 * cannot break because a third-party script went away.
 *
 * Paths are relative ("../v1/mcps") so the app works whether it is served from
 * /ui/ or from behind a path-prefixing proxy.
 *
 * The form is deliberately tiny. Rather than asking the user to pre-answer
 * every question the pipeline might have, it sends one free-form input to
 * POST /v1/resolve and renders what comes back: the inferences the server made,
 * and only the questions it genuinely could not settle. Answers go back as
 * `overrides` and we resolve again, converging until `ready`.
 *
 * Crucially, Create submits `plan.request` -- the exact request the server
 * resolved -- so what is shown is what runs.
 */
"use strict";

const API = "..";
const STAGES = ["ingest", "deploy", "oauth", "register", "authorize", "connect", "attach"];
const TERMINAL = (state) =>
  state === "READY" || state === "FAILED" || state === "PARTIAL" || state.startsWith("STOPPED");

/* Order and captions for the per-record configuration view. `preflight` is
 * absent from STAGES (it has no dot in the list) but does record config, so
 * the two lists are deliberately different. */
const CONFIG_SECTIONS = [
  ["request", "what was submitted, before any defaults were applied"],
  ["preflight", "inputs after presets and provider defaults; project and locations"],
  ["ingest", "documentation source and the manifest derived from it"],
  ["deploy", "Cloud Run service and the manifest handed to the runtime"],
  ["oauth", "credential strategy and the authorization server in play"],
  ["register", "Agent Registry service and the published tool spec"],
  ["authorize", "the Discovery Engine Authorization resource"],
  ["connect", "the exact setUpDataConnector request body"],
  ["attach", "the Gemini Enterprise app binding"],
];

/* Advanced overrides. Each maps to an `overrides` key understood by
 * /v1/resolve, so the advanced panel round-trips through the same resolution
 * the rest of the form uses rather than patching the request behind its back. */
const ADVANCED_FIELDS = [
  "name",
  "base_url",
  "auth_kind",
  "scopes",
  "api_key",
  "api_key_header",
  "authorization_endpoint",
  "token_endpoint",
  "stop_after",
];

/* Overrides that carry a credential. They are sent to /v1/resolve like any
 * other, but must never be echoed back into the DOM or kept in the form after
 * the run starts -- the server fingerprints them on the record, and the browser
 * should be no more careless than the server. */
const SECRET_FIELDS = new Set(["api_key", "client_secret"]);

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

async function api(path, options = {}) {
  const resp = await fetch(`${API}${path}`, {
    headers: { "content-type": "application/json", accept: "application/json" },
    ...options,
  });
  const text = await resp.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = { detail: text }; }
  if (!resp.ok) {
    const detail = body?.detail ?? body?.error_description ?? body?.error ?? text;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail, null, 2));
  }
  return body;
}

/* ------------------------------------------------------------------ */
/* Health                                                              */
/* ------------------------------------------------------------------ */

async function loadHealth() {
  const el = $("#health");
  try {
    // /readyz was trimmed to a bare liveness signal -- it is reachable
    // unauthenticated by the Cloud Run startup probe, so it can no longer
    // carry the project and region it used to. That detail now lives behind
    // auth at /v1/buildinfo.
    const r = await api("/v1/buildinfo");
    el.textContent = `${r.project} · ${r.run_region}`;
    el.className = "pill pill-ok";
    el.title = `Agent Registry: ${r.agent_registry_location}\nDiscovery Engine: ${r.discovery_engine_location}\nPublic URL: ${r.public_base_url}`;
  } catch (err) {
    el.textContent = "unreachable";
    el.className = "pill pill-err";
    el.title = String(err.message || err);
  }
}

/* ------------------------------------------------------------------ */
/* Copy buttons (shared by findings, questions and the drawer)         */
/* ------------------------------------------------------------------ */

function renderAction(a) {
  const bits = [];
  if (a.url) {
    bits.push(`<a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.text)}</a>`);
  } else {
    bits.push(esc(a.text));
  }
  let html = `<div class="req-action">${bits.join("")}`;
  const value = a.copy ?? a.copy_value;
  if (value) {
    html += `<div class="copyrow"><code>${esc(value)}</code>` +
            `<button type="button" class="copybtn" data-copy="${esc(value)}">Copy</button></div>`;
  }
  if (a.cli) {
    html += `<div class="copyrow"><code>${esc(a.cli)}</code>` +
            `<button type="button" class="copybtn" data-copy="${esc(a.cli)}">Copy</button></div>`;
  }
  return html + "</div>";
}

function wireCopyButtons(host) {
  host.querySelectorAll(".copybtn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
      } catch {
        // Clipboard API needs a secure context; select the text instead.
        const code = btn.previousElementSibling;
        const range = document.createRange();
        range.selectNodeContents(code);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
      const label = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("done");
      setTimeout(() => { btn.textContent = label; btn.classList.remove("done"); }, 1400);
    });
  });
}

/* ------------------------------------------------------------------ */
/* Resolution                                                          */
/* ------------------------------------------------------------------ */

/** Answers to questions, plus advanced overrides. Sent back on every resolve. */
let answers = {};
/** The most recent ResolvedPlan. `plan.request` is what Create submits. */
let plan = null;
let resolveTimer = null;
let resolveSeq = 0;

function collectAdvanced() {
  for (const name of ADVANCED_FIELDS) {
    const el = $(`#adv-${name}`);
    if (!el) continue;
    const value = (el.value || "").trim();
    if (value) answers[name] = value;
    else delete answers[name];
  }
}

/** Wipe credential inputs and the answers derived from them. */
function clearSecretInputs() {
  for (const name of SECRET_FIELDS) {
    const el = $(`#adv-${name}`);
    if (el) el.value = "";
    delete answers[name];
  }
}

function setStatus(text) {
  $("#analysis-status").textContent = text || "";
}

/**
 * Ask the server what this input is and what is still missing.
 *
 * Sequence-numbered because resolution involves network probes and a slow
 * answer for an old input must not overwrite a fast answer for a new one.
 */
async function doResolve() {
  const input = ($("#input").value || "").trim();
  const description = ($("#description").value || "").trim();
  showError("");

  if (!input) {
    plan = null;
    $("#analysis").classList.add("hidden");
    setStatus("");
    return;
  }

  collectAdvanced();
  const seq = ++resolveSeq;
  setStatus("Analysing…");

  let result;
  try {
    result = await api("/v1/resolve", {
      method: "POST",
      body: JSON.stringify({ input, description, overrides: answers }),
    });
  } catch (err) {
    if (seq !== resolveSeq) return;
    setStatus("");
    showError(err.message || String(err));
    return;
  }
  if (seq !== resolveSeq) return; // superseded

  plan = result;
  setStatus("");
  renderAnalysis(result);
}

function scheduleResolve(delay = 700) {
  clearTimeout(resolveTimer);
  resolveTimer = setTimeout(doResolve, delay);
}

const FINDING_ICON = { certain: "&check;", likely: "~" };
const FINDING_CLASS = { certain: "req-ok", likely: "req-auto" };

function renderFinding(f) {
  return `
    <div class="req">
      <div class="req-icon ${FINDING_CLASS[f.confidence] || "req-ok"}">${
        FINDING_ICON[f.confidence] || "&check;"
      }</div>
      <div style="flex:1">
        <div class="req-title">${esc(f.title)}${
          f.confidence === "likely" ? ' <span class="pill pill-muted">inferred</span>' : ""
        }</div>
        ${f.detail ? `<div class="req-detail">${esc(f.detail)}</div>` : ""}
      </div>
    </div>`;
}

function renderField(question, field) {
  const id = `q-${question.id}-${field.name}`;
  const value = esc(field.value ?? "");
  if (field.kind === "select") {
    const options = field.options
      .map((o) => `<option value="${esc(o.value)}"${
        o.value === field.value ? " selected" : ""
      }>${esc(o.label)}</option>`)
      .join("");
    return `<label><span class="label">${esc(field.label)}</span>
      <select id="${esc(id)}" data-answer="${esc(field.name)}">
        <option value="">Choose…</option>${options}
      </select></label>`;
  }
  const type = field.kind === "password" ? "password" : "text";
  return `<label><span class="label">${esc(field.label)}</span>
    <input id="${esc(id)}" type="${type}" data-answer="${esc(field.name)}"
      placeholder="${esc(field.placeholder || "")}" value="${value}" /></label>`;
}

function renderQuestion(q) {
  return `
    <div class="req">
      <div class="req-icon ${q.blocking ? "req-man" : "req-auto"}">${q.blocking ? "!" : "?"}</div>
      <div style="flex:1">
        <div class="req-title">${esc(q.title)}${
          q.blocking ? "" : ' <span class="pill pill-muted">optional</span>'
        }</div>
        ${q.detail ? `<div class="req-detail">${esc(q.detail)}</div>` : ""}
        ${q.fields.length ? `<div class="grid-2">${
          q.fields.map((f) => renderField(q, f)).join("")
        }</div>` : ""}
        ${q.actions?.length ? `<div class="req-actions">${
          q.actions.map(renderAction).join("")
        }</div>` : ""}
      </div>
    </div>`;
}

/**
 * Replace the analysis panel without stealing the cursor.
 *
 * Questions render input fields, and resolution re-runs while they are being
 * filled in, so a naive innerHTML swap destroys the element the user is typing
 * into. Identical output is skipped outright; otherwise focus and caret are
 * restored afterwards. (The same hazard is why the drawer tracks `cfgOpen`.)
 */
function paint(host, html) {
  if (host.innerHTML === html) return false;

  const active = document.activeElement;
  const key = active && host.contains(active) ? active.dataset.answer : null;
  const start = key ? active.selectionStart : null;
  const end = key ? active.selectionEnd : null;

  host.innerHTML = html;

  if (key) {
    const restored = host.querySelector(`[data-answer="${CSS.escape(key)}"]`);
    if (restored) {
      restored.focus();
      try { restored.setSelectionRange(start, end); } catch { /* selects */ }
    }
  }
  return true;
}

function renderAnalysis(p) {
  const host = $("#analysis");
  host.classList.remove("hidden");

  if (p.error) {
    paint(host, `<div class="banner err">${esc(p.error)}</div>`);
    return;
  }

  const tools = p.tools || [];
  const html = `
    <div class="banner ${p.ready ? "ok" : ""}">${esc(p.summary)}</div>
    ${(p.findings || []).map(renderFinding).join("")}
    ${(p.questions || []).map(renderQuestion).join("")}
    ${tools.length ? `
      <div class="section-title">Tools (${tools.length})</div>
      ${tools.slice(0, 25).map((t) => `
        <div class="tool-row">
          <div>
            <div class="tool-name">${esc(t.name)}</div>
            ${t.description ? `<div class="muted" style="font-size:11.5px">${
              esc(t.description)
            }</div>` : ""}
          </div>
        </div>`).join("")}` : ""}
  `;

  if (!paint(host, html)) return;
  wireCopyButtons(host);

  /* Answers commit on `change` -- i.e. when the field is left -- deliberately
   * not on `input`. Re-resolving mid-keystroke would rebuild this panel under
   * the cursor, which made it impossible to finish typing a client secret. */
  host.querySelectorAll("[data-answer]").forEach((el) => {
    el.addEventListener("change", () => {
      const value = (el.value || "").trim();
      if (value) answers[el.dataset.answer] = value;
      else delete answers[el.dataset.answer];
      scheduleResolve(0);
    });
  });
}

function showError(message) {
  const el = $("#form-error");
  el.textContent = message;
  el.classList.toggle("hidden", !message);
}

/* ------------------------------------------------------------------ */
/* Provisioning                                                        */
/* ------------------------------------------------------------------ */

async function submitCreate(event) {
  event.preventDefault();
  showError("");

  // Resolution may still be in flight, or the user may never have blurred the
  // field. Settle it before creating anything.
  clearTimeout(resolveTimer);
  await doResolve();

  if (!plan) {
    showError("Provide API documentation, a spec, or an MCP URL first.");
    return;
  }
  if (!plan.request) {
    // Nothing coherent to submit -- usually a missing description.
    showError(plan.error || plan.summary || "Not enough information yet.");
    return;
  }

  /* Not ready is a warning, not a wall. Requirement detection can be wrong,
   * and the operator may know something we do not, so let them through after
   * saying plainly what is expected to break. */
  const blocking = (plan.questions || []).filter((q) => q.blocking);
  if (blocking.length) {
    const ok = confirm(
      `${blocking.length} thing(s) still needed:\n\n` +
      blocking.map((q) => `\u2022 ${q.title}`).join("\n") +
      "\n\nCreate anyway? The run will likely fail at that stage."
    );
    if (!ok) return;
  }

  const button = $("#btn-create");
  button.disabled = true;
  button.textContent = "Working…";
  try {
    // Submit exactly what was resolved, so the plan shown is the plan run.
    const accepted = await api("/v1/mcps", {
      method: "POST",
      body: JSON.stringify(plan.request),
    });
    /* The key is now in Secret Manager. Leaving it in the form means the next
     * resolve re-sends it, and it sits in the DOM for as long as the tab is
     * open -- neither is necessary once the run owns it. */
    clearSecretInputs();
    await refreshList();
    if (accepted?.id) {
      openDrawer(accepted.id);
      pollUntilDone(accepted.id);
    }
  } catch (err) {
    showError(err.message || String(err));
  } finally {
    button.disabled = false;
    button.textContent = "Create";
  }
}

let listTimer = null;
//: Ids currently being deleted. Polling must not re-render over them.
const deleting = new Set();

/** Human summary of what a delete will actually remove. */
function deletionPlan(r) {
  const removes = [];
  if (r.cloud_run_url) removes.push("the Cloud Run service");
  if (r.registry_service) removes.push("the Agent Registry entry");
  if (r.authorization) removes.push("the Discovery Engine authorization");
  if (r.datastore) removes.push("the Gemini Enterprise data store and collection");
  if (!removes.length) removes.push("the record");
  return removes;
}

/**
 * Delete an MCP. Returns true when it went through.
 *
 * The data store is detached from the app before the collection is deleted:
 * a still-attached data store makes its collection permanently undeletable.
 */
async function deleteMcp(record, { onStatus } = {}) {
  const removes = deletionPlan(record);
  const warn = record.datastore
    ? `\n\nThe data store will be detached from any Gemini Enterprise app that uses it.`
    : "";
  const ok = confirm(
    `Delete "${record.display_name || record.id}"?\n\nThis removes:\n` +
    removes.map((x) => `\u2022 ${x}`).join("\n") + warn
  );
  if (!ok) return false;

  deleting.add(record.id);
  onStatus?.("Deleting\u2026");
  try {
    const out = await api(`/v1/mcps/${encodeURIComponent(record.id)}`, { method: "DELETE" });
    const leftover = out.manual_cleanup_required || [];
    const errors = out.errors || [];
    if (errors.length) {
      onStatus?.(`Deleted with warnings: ${errors.join("; ")}`);
    } else if (leftover.length) {
      onStatus?.(`Deleted. Still needs manual cleanup: ${leftover.join(", ")}`);
    } else {
      onStatus?.("Deleted.");
    }
    return true;
  } catch (err) {
    onStatus?.(String(err.message || err));
    return false;
  } finally {
    deleting.delete(record.id);
  }
}

function stateClass(state) {
  if (state === "READY") return "pill-ok";
  if (state === "FAILED") return "pill-err";
  if (state === "RUNNING") return "pill-run";
  // PARTIAL and STOPPED_* both mean "stopped somewhere useful", which is
  // neither success nor failure and should not be coloured like either.
  return "pill-warn";
}

/**
 * Retry a run from where it stopped.
 *
 * Deliberately offered instead of "delete and try again": the earlier stages
 * created resources that cannot simply be recreated (Agent Registry interface
 * URLs are unique per location), so starting over fails at `register` whatever
 * the original problem was.
 */
async function resumeMcp(record, { onStatus } = {}) {
  onStatus?.("Resuming\u2026");
  try {
    const out = await api(`/v1/mcps/${encodeURIComponent(record.id)}/resume`, { method: "POST" });
    const reusing = (out.reusing || []).join(", ");
    onStatus?.(
      `Retrying ${out.resuming_from || "the remaining steps"}` +
      (reusing ? `; keeping ${reusing}.` : ".")
    );
    return true;
  } catch (err) {
    onStatus?.(String(err.message || err));
    return false;
  }
}

function stageDots(record) {
  const byName = new Map((record.stages || []).map((s) => [s.stage, s]));
  const running = record.state === "RUNNING";
  const doneCount = (record.stages || []).length;
  return `<div class="stages">${STAGES.map((name, i) => {
    const s = byName.get(name);
    let cls = "";
    if (s) cls = s.ok ? "ok" : "err";
    else if (running && i === doneCount) cls = "run";
    return `<span class="stage-dot ${cls}" title="${esc(name)}${s ? `: ${esc(s.detail)}` : ""}"></span>`;
  }).join("")}</div>`;
}

async function refreshList() {
  const host = $("#mcp-list");
  try {
    const records = await api("/v1/mcps");
    if (!records.length) {
      host.innerHTML = `<p class="muted">Nothing provisioned yet. Create one on the left.</p>`;
      return records;
    }
    const sorted = records.slice().sort((a, b) => String(a.id).localeCompare(String(b.id)));
    host.innerHTML = sorted
      .map((r) => `
        <div class="card" data-id="${esc(r.id)}">
          <div class="card-top">
            <div>
              <div class="card-title">${esc(r.display_name || r.id)}</div>
              <div class="card-id">${esc(r.id)}</div>
            </div>
            <div class="card-right">
              <span class="pill ${stateClass(r.state)}">${esc(r.state)}</span>
              <button type="button" class="iconbtn" data-del="${esc(r.id)}"
                      title="Delete ${esc(r.display_name || r.id)}"
                      aria-label="Delete ${esc(r.display_name || r.id)}">&times;</button>
            </div>
          </div>
          ${r.description ? `<p class="card-desc">${esc(r.description)}</p>` : ""}
          ${sourceLabel(r) ? `<div class="card-src" title="Open for the full configuration">${esc(sourceLabel(r))}</div>` : ""}
          ${stageDots(r)}
          <div class="card-status muted" data-status="${esc(r.id)}"></div>
        </div>`).join("");

    const byId = new Map(sorted.map((r) => [r.id, r]));

    host.querySelectorAll(".card").forEach((card) =>
      card.addEventListener("click", () => openDrawer(card.dataset.id)));

    host.querySelectorAll("[data-del]").forEach((btn) =>
      btn.addEventListener("click", async (event) => {
        // Otherwise the click also opens the detail drawer underneath.
        event.stopPropagation();
        const id = btn.dataset.del;
        const status = host.querySelector(`[data-status="${CSS.escape(id)}"]`);
        btn.disabled = true;
        const done = await deleteMcp(byId.get(id), {
          onStatus: (msg) => { if (status) status.textContent = msg; },
        });
        if (done) {
          if (currentDrawerId === id) closeDrawer();
          await refreshList();
        } else {
          btn.disabled = false;
        }
      }));
    return sorted;
  } catch (err) {
    host.innerHTML = `<p class="error">${esc(err.message || err)}</p>`;
    return [];
  }
}

function pollUntilDone(id) {
  clearTimeout(listTimer);
  const tick = async () => {
    if (deleting.size) { listTimer = setTimeout(tick, 3000); return; }
    const records = await refreshList();
    if ($("#drawer").classList.contains("hidden") === false && currentDrawerId === id
        && !deleting.has(currentDrawerId)) {
      await openDrawer(id, true);
    }
    const target = records.find((r) => r.id === id);
    const anyRunning = records.some((r) => r.state === "RUNNING");
    if ((target && !TERMINAL(target.state)) || anyRunning) {
      listTimer = setTimeout(tick, 3000);
    }
  };
  listTimer = setTimeout(tick, 2000);
}

/* ------------------------------------------------------------------ */
/* Detail drawer                                                       */
/* ------------------------------------------------------------------ */

let currentDrawerId = null;

function row(label, value, isLink) {
  if (!value) return "";
  const body = isLink
    ? `<a href="${esc(value)}" target="_blank" rel="noopener">${esc(value)}</a>`
    : esc(value);
  return `<dt>${esc(label)}</dt><dd>${body}</dd>`;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/* How much is actually known about a tool's method and path.
 *
 * Only the weak cases are marked. Tools read from a specification are the norm
 * and badging all of them would turn the list into noise, so silence means
 * "from a spec" and a badge means "treat this one with suspicion". */
function evidenceBadge(t) {
  if (t.evidence === "inferred") {
    return ` <span class="muted" style="font-size:10.5px" title="${
      esc(t.evidence_note || "not confirmed against the live API")
    }">inferred</span>`;
  }
  if (t.evidence === "probed") {
    return ` <span class="muted" style="font-size:10.5px" title="${
      esc(t.evidence_note || "confirmed by a read-only request")
    }">probed</span>`;
  }
  return "";
}

/** One-line provenance for a record: where its tools came from. */
function sourceLabel(r) {
  const req = r.request || {};
  if (req.mcp_url) return `existing MCP \u00b7 ${req.mcp_url}`;
  /* Records written before merge support stored a single object rather than
   * a list, and they are still served from Firestore. Accept both. */
  const docs = Array.isArray(req.docs) ? req.docs : req.docs ? [req.docs] : [];
  const described = docs.filter((d) => d?.kind);
  if (described.length) {
    const one = (d) =>
      d.kind.endsWith("url")
        ? `${d.kind} \u00b7 ${d.value}`
        : `${d.kind} \u00b7 ${d.length} chars${
            d.truncated ? " (truncated in this record)" : ""
          }`;
    if (described.length === 1) return one(described[0]);
    return `${described.length} sources \u00b7 ${described.map(one).join("; ")}`;
  }
  const kind = r.manifest?.source?.kind;
  return kind ? `${kind} source` : "";
}

/* Which <details> the user has opened, by key. The drawer re-renders itself
 * every 3s while a run is live; without this, reading a config block during a
 * run is impossible because it snaps shut under the cursor. */
const cfgOpen = new Map();

/**
 * A collapsible pretty-printed JSON block with a copy button.
 *
 * The button sits after the <pre> so wireCopyButtons' clipboard fallback
 * (select previousElementSibling) selects the JSON rather than the caption.
 */
function jsonBlock(key, name, caption, value, defaultOpen) {
  const text = JSON.stringify(value, null, 2);
  const open = cfgOpen.has(key) ? cfgOpen.get(key) : !!defaultOpen;
  return `
    <details class="cfg" data-cfg="${esc(key)}"${open ? " open" : ""}>
      <summary><code>${esc(name)}</code> <span class="muted">${esc(caption)}</span></summary>
      <pre class="json">${esc(text)}</pre>
      <button type="button" class="copybtn" data-copy="${esc(text)}">Copy JSON</button>
    </details>`;
}

function wireConfigToggles(host) {
  host.querySelectorAll("details[data-cfg]").forEach((el) =>
    el.addEventListener("toggle", () => cfgOpen.set(el.dataset.cfg, el.open)));
}

function isEmpty(value) {
  return value == null || (typeof value === "object" && !Object.keys(value).length);
}

/**
 * Every input and derived setting the run used, per stage.
 *
 * The failing stage is expanded by default: when a run breaks, the request
 * body that broke it is the first thing anyone wants to read, and having to
 * hunt for it defeats the purpose of recording it.
 */
function renderConfig(r) {
  const failed = (r.stages || []).find((s) => !s.ok)?.stage;
  const blocks = CONFIG_SECTIONS.map(([key, caption]) => {
    const value = key === "request" ? r.request : r.config?.[key];
    if (isEmpty(value)) return "";
    return jsonBlock(`cfg:${key}`, key, caption, value, key === failed);
  }).filter(Boolean);

  if (!blocks.length) {
    return `<div class="section-title">Configuration</div>
      <p class="muted">No configuration recorded. Runs created before this build
      do not have one; re-provision to capture it.</p>`;
  }

  const whole = JSON.stringify(r, null, 2);
  return `
    <div class="section-title">Configuration</div>
    <p class="muted cfg-note">Secrets are shown as a <code>***</code> fingerprint: identical
      values fingerprint identically, so you can tell two runs apart without exposing them.</p>
    ${blocks.join("")}
    <div class="actions">
      <button type="button" class="copybtn" data-copy="${esc(whole)}">Copy whole record</button>
    </div>`;
}

/* ------------------------------------------------------------------ */
/* Generated package                                                   */
/* ------------------------------------------------------------------ */

/* Fetched packages, by mcp id, as `{state, bundle}`.
 *
 * The drawer re-renders every 3s while a run is live, and the package is a
 * separate request, so without a cache the file you were reading would vanish
 * and be re-fetched on every tick. Cached rather than folded into the record
 * because it is only wanted when asked for: assembling it reads the runtime
 * source off disk, which is not worth doing for every drawer open.
 *
 * The record's state is stored with it because a resume can re-run `ingest`
 * and produce a different manifest. Serving the pre-resume package from cache
 * would show code that is no longer what is deployed -- the precise failure
 * this feature exists to prevent -- so a state change invalidates the entry. */
const bundleCache = new Map();

const KIND_LABEL = {
  manifest: "manifest",
  runtime: "runtime",
  record: "record",
  docs: "docs",
};

function humanBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * One file, collapsed, with its full contents and a copy button.
 *
 * Reuses the `cfg` details styling and the cfgOpen registry so an open file
 * survives the drawer's polling re-render, exactly like a config block.
 */
function bundleFileBlock(mcpId, f) {
  const key = `pkg:${mcpId}:${f.path}`;
  const open = cfgOpen.has(key) ? cfgOpen.get(key) : false;
  return `
    <details class="cfg" data-cfg="${esc(key)}"${open ? " open" : ""}>
      <summary>
        <code>${esc(f.path)}</code>
        <span class="muted">${esc(KIND_LABEL[f.kind] || f.kind)} &middot; ${esc(humanBytes(f.bytes))} &middot; ${esc(f.description)}</span>
      </summary>
      <pre class="json">${esc(f.content)}</pre>
      <button type="button" class="copybtn" data-copy="${esc(f.content)}">Copy file</button>
      <div class="muted pkg-hash">sha256 ${esc(f.sha256)}</div>
    </details>`;
}

function renderBundle(mcpId, b) {
  const warnings = (b.warnings || []).map((w) => `
    <div class="req">
      <div class="req-icon req-man">!</div>
      <div style="flex:1"><div class="req-detail">${esc(w)}</div></div>
    </div>`).join("");

  return `
    <p class="muted cfg-note">
      Nothing here was written by a model. Every MCP server runs the same
      <code>server.py</code>; <code>manifest.json</code> is the only thing that
      differs between two of them. Together they are the whole deployment, so
      this package builds and runs it locally.
    </p>
    ${warnings}
    <div class="pkg-meta">
      <span class="muted">${b.files.length} files &middot; ${esc(humanBytes(b.total_bytes))}</span>
      <span class="muted" title="Content hash of the package. Unchanged input always produces this same value, so you can tell whether anything moved since you last reviewed it.">fingerprint <code>${esc(b.fingerprint)}</code></span>
    </div>
    ${b.files.map((f) => bundleFileBlock(mcpId, f)).join("")}
    <div class="actions">
      <a class="btn btn-sm" href="${API}${esc(b.download_url)}" download="${esc(b.filename)}">Download .zip</a>
    </div>`;
}

/** Fetch (or replay) the package for a record in `state` and paint it. */
async function loadBundle(mcpId, state) {
  const host = $("#pkg-host");
  if (!host) return;

  const hit = bundleCache.get(mcpId);
  let b = hit && hit.state === state ? hit.bundle : null;
  if (!b) {
    host.innerHTML = `<p class="muted">Assembling package…</p>`;
    try {
      b = await api(`/v1/mcps/${encodeURIComponent(mcpId)}/bundle`);
      bundleCache.set(mcpId, { state, bundle: b });
    } catch (err) {
      host.innerHTML = `<p class="error">${esc(err.message || err)}</p>`;
      return;
    }
  }
  // The drawer may have been closed or switched while the request was in
  // flight; painting then would put one record's files under another's title.
  if (currentDrawerId !== mcpId) return;
  host.innerHTML = renderBundle(mcpId, b);
  wireCopyButtons(host);
  wireConfigToggles(host);
}

/**
 * The package section, loaded on demand.
 *
 * Not fetched with the record: it is a second request that reads files off
 * disk, and most drawer opens are to check a run's state rather than to audit
 * its contents. Once loaded it stays loaded, because the cache survives the
 * re-render.
 */
function renderBundleSection(r) {
  if (!r.manifest) return "";
  return `
    <div class="section-title">Generated package</div>
    <div id="pkg-host">
      <div class="actions">
        <button type="button" class="btn btn-sm" id="btn-pkg-load">Show generated code</button>
        <a class="btn btn-sm" href="${API}/v1/mcps/${encodeURIComponent(r.id)}/bundle.zip" download>Download .zip</a>
      </div>
    </div>`;
}

/* ------------------------------------------------------------------ */
/* Failure diagnosis                                                   */
/* ------------------------------------------------------------------ */

/** Ids whose diagnosis has been requested, so polling does not re-request. */
const diagnosing = new Set();

/**
 * Explain a failure before showing the raw error.
 *
 * The upstream message names a field in a request body the user never wrote,
 * in an API they may not know exists. It is kept -- it is the ground truth --
 * but demoted below the explanation, and the two are visually distinct so it
 * is obvious which is Google talking and which is us.
 */
function renderDiagnosis(r) {
  const d = r.diagnosis;
  if (!d) {
    return `
      <div class="banner err" style="white-space:pre-wrap">${esc(r.error)}</div>
      <div class="req-detail" id="diag-pending">Working out what to do about this…</div>`;
  }

  const steps = (d.steps || []).map(renderAction).join("");
  return `
    <div class="banner err"><strong>${esc(d.summary)}</strong></div>
    ${d.likely_app_bug ? `
      <div class="req">
        <div class="req-icon req-auto">i</div>
        <div style="flex:1"><div class="req-title">This looks like a bug in prompt-to-mcp</div>
        <div class="req-detail">Not something you configured wrongly. Nothing you change
        on your side is expected to fix it.</div></div>
      </div>` : ""}
    ${d.cause ? `<div class="req-detail" style="margin:8px 0">${esc(d.cause)}</div>` : ""}
    ${steps ? `<div class="section-title">What to do</div>
      <div class="req-actions">${steps}</div>` : ""}
    <details class="cfg" data-cfg="raw-error">
      <summary><code>raw error</code> <span class="muted">exactly what the API returned${
        d.source === "model" ? " · explanation generated by Gemini" : ""
      }</span></summary>
      <pre class="json">${esc(r.error)}</pre>
    </details>`;
}

/**
 * Fetch the explanation for a failed run, once.
 *
 * Deterministic diagnoses are attached when the run fails, so this usually
 * returns instantly from cache; only novel failures cost a model call.
 */
async function ensureDiagnosis(id, record) {
  if (!record.error || record.diagnosis || diagnosing.has(id)) return;
  diagnosing.add(id);
  try {
    const d = await api(`/v1/mcps/${encodeURIComponent(id)}/diagnose`, { method: "POST" });
    if (currentDrawerId === id) {
      record.diagnosis = d;
      const pending = $("#diag-pending");
      if (pending) await openDrawer(id, true);
    }
  } catch (err) {
    const pending = $("#diag-pending");
    if (pending) pending.textContent = `Could not explain this failure: ${err.message || err}`;
  } finally {
    diagnosing.delete(id);
  }
}

async function openDrawer(id, silent) {
  currentDrawerId = id;
  const drawer = $("#drawer");
  drawer.classList.remove("hidden");
  if (!silent) $("#drawer-body").innerHTML = `<p class="muted">Loading…</p>`;

  let r;
  try {
    r = await api(`/v1/mcps/${encodeURIComponent(id)}`);
  } catch (err) {
    $("#drawer-body").innerHTML = `<p class="error">${esc(err.message || err)}</p>`;
    return;
  }

  $("#drawer-title").textContent = r.display_name || r.id;
  const mcpUrl = r.cloud_run_url ? `${r.cloud_run_url.replace(/\/$/, "")}/mcp` : null;
  const tools = r.manifest?.tools || [];

  $("#drawer-body").innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span class="pill ${stateClass(r.state)}">${esc(r.state)}</span>
      <span class="card-id">${esc(r.id)}</span>
    </div>
    ${r.state === "PARTIAL" ? `
      <div class="req">
        <div class="req-icon req-auto">i</div>
        <div style="flex:1"><div class="req-title">Your MCP server is deployed and working</div>
        <div class="req-detail">It stopped at <code>${esc(r.failed_stage || "a later step")}</code>,
        which only connects it to Gemini Enterprise. Everything before that succeeded and is
        usable now.</div></div>
      </div>` : ""}
    ${r.error ? renderDiagnosis(r) : ""}
    ${(r.requirements || []).some((x) => x.blocking && x.status === "manual") ? `
      <div class="section-title">What's needed</div>
      ${r.requirements.filter((x) => x.blocking && x.status === "manual").map((x) => `
        <div class="req">
          <div class="req-icon req-man">!</div>
          <div style="flex:1">
            <div class="req-title">${esc(x.title)}</div>
            <div class="req-detail">${esc(x.detail)}</div>
            ${x.actions?.length ? `<div class="req-actions">${x.actions.map(renderAction).join("")}</div>` : ""}
          </div>
        </div>`).join("")}` : ""}

    <div class="section-title">Resources</div>
    <dl class="kv">
      ${row("Cloud Run", r.cloud_run_url, true)}
      ${row("MCP endpoint", mcpUrl, true)}
      ${row("Agent Registry", r.registry_service)}
      ${row("MCP server", r.registry_resource)}
      ${row("Authorization", r.authorization)}
      ${row("Collection", r.collection)}
      ${row("Data store", r.datastore)}
      ${row("OAuth client", r.proxy_client_id)}
    </dl>

    <div class="section-title">Pipeline</div>
    <div class="timeline">
      ${STAGES.map((name) => {
        const s = (r.stages || []).find((x) => x.stage === name);
        const cls = s ? (s.ok ? "ok" : "err") : "";
        return `<div class="tl-item ${cls}">
          <div class="tl-stage">${esc(name)}</div>
          <div class="tl-detail">${s ? esc(s.detail) : "<span style='opacity:.5'>pending</span>"}
            ${isEmpty(s?.data) ? "" : jsonBlock(`out:${name}`, "outputs", "", s.data, false)}</div>
        </div>`;
      }).join("")}
    </div>

    ${renderConfig(r)}

    ${tools.length ? `
      <div class="section-title">Tools (${tools.length})</div>
      ${tools.map((t) => `
        <div class="tool-row">
          <span class="method">${esc(t.method)}</span>
          <div>
            <div class="tool-name">${esc(t.name)}${evidenceBadge(t)}</div>
            <div class="tool-path">${esc(t.path)}</div>
          </div>
        </div>`).join("")}` : ""}

    ${renderBundleSection(r)}

    <div class="section-title">Actions</div>
    <div class="actions">
      ${mcpUrl ? `<a class="btn btn-sm" href="${esc(mcpUrl)}" target="_blank" rel="noopener">Open MCP endpoint</a>` : ""}
      ${r.state !== "READY" && r.state !== "RUNNING"
        ? `<button type="button" class="btn btn-sm" id="btn-resume">Retry from ${esc(r.failed_stage || "where it stopped")}</button>`
        : ""}
      <button type="button" class="btn btn-sm btn-danger" id="btn-delete">Delete</button>
    </div>
    <p id="delete-msg" class="muted"></p>
  `;

  wireCopyButtons($("#drawer-body"));
  wireConfigToggles($("#drawer-body"));
  ensureDiagnosis(id, r);

  const pkg = $("#btn-pkg-load");
  if (pkg) pkg.addEventListener("click", () => loadBundle(id, r.state));
  // Already fetched (this is a polling re-render, or the drawer was reopened):
  // repaint it rather than making the user ask a second time.
  if (bundleCache.has(id)) loadBundle(id, r.state);

  const resume = $("#btn-resume");
  if (resume) {
    resume.addEventListener("click", async () => {
      resume.disabled = true;
      await resumeMcp(r, { onStatus: (msg) => { $("#delete-msg").textContent = msg; } });
      await refreshList();
      // Reopen so the run is watched live from RUNNING onwards.
      await openDrawer(id, true);
    });
  }

  const del = $("#btn-delete");
  if (del) {
    del.addEventListener("click", async () => {
      del.disabled = true;
      const done = await deleteMcp(r, {
        onStatus: (msg) => { $("#delete-msg").textContent = msg; },
      });
      await refreshList();
      if (done) {
        bundleCache.delete(id);
        setTimeout(closeDrawer, 1200);
      } else {
        del.disabled = false;
      }
    });
  }
}

function closeDrawer() {
  currentDrawerId = null;
  $("#drawer").classList.add("hidden");
}

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

function init() {
  $("#create-form").addEventListener("submit", submitCreate);

  // Resolve on blur (immediate) and after a pause in typing. Probing costs a
  // round trip, so we do not do it on every keystroke.
  $("#input").addEventListener("blur", () => { clearTimeout(resolveTimer); doResolve(); });
  $("#input").addEventListener("input", () => scheduleResolve());
  $("#description").addEventListener("blur", () => {
    if (($("#input").value || "").trim()) { clearTimeout(resolveTimer); doResolve(); }
  });

  ADVANCED_FIELDS.forEach((name) => {
    const el = $(`#adv-${name}`);
    if (el) el.addEventListener("change", () => scheduleResolve(0));
  });

  $("#btn-refresh").addEventListener("click", refreshList);
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  loadHealth();
  refreshList().then((records) => {
    if (records.some((r) => r.state === "RUNNING")) pollUntilDone(null);
  });
}

document.addEventListener("DOMContentLoaded", init);
