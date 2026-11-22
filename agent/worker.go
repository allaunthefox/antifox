package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"antifox/db"
	"antifox/engine/agentcore"
	"antifox/engine/harness"
	"antifox/engine/llm"
	"antifox/engine/memory"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), or "tavily"
// (TavilyKey required). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
}

type Worker struct {
	prov        llm.Provider
	model       string
	workDir     string
	proxyAddr   string
	proxyCACert string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	mem         *memory.Store     // cross-engagement tradecraft memory (G4)
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// trafficResolver, if set, resolves a finding's reproduction steps to real
	// recorded traffic exchange ids at record time (host callback). nil = no linkage.
	trafficResolver func(taskID int64, repro json.RawMessage) json.RawMessage
}

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleHardGrace is how far past the soft wall-clock budget (runTimeout) the hard
// ctx deadline sits — a backstop for a hung turn; the soft budget handles the
// normal case at the turn boundary.
const settleHardGrace = 90 * time.Second

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "You are about to be terminated because your budget is exhausted. Do not run any more commands/probes. In order: (1) write back, one by one, the content you have identified above but not yet stored — new assets with insert_assets, exploration conclusions/facts with record_fact, confirmed vulnerabilities with report_finding; (2) **finally, in one standalone plain-text sentence**, summarize what you did and the key conclusions you reached (this sentence will be shown as the result of this run — make sure to output it)."

// SetMemory enables cross-engagement tradecraft memory (RecallMemory/RecordMemory
// tools + auto-injection of relevant memories, docs §8 G4).
func (w *Worker) SetMemory(m *memory.Store) { w.mem = m }

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// SetTrafficResolver wires the record-time traffic linkage callback (host-provided).
func (w *Worker) SetTrafficResolver(fn func(taskID int64, repro json.RawMessage) json.RawMessage) {
	w.trafficResolver = fn
}

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the recording proxy and makes the common toolchain trust its MITM CA — so tools
// need no manual -x/--proxy/-k. Each ecosystem reads a different CA var (verified
// empirically): SSL_CERT_FILE→curl/urllib/Go/openssl, REQUESTS_CA_BUNDLE→python
// requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl, GIT_SSL_CAINFO→git,
// NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+ honor the proxy vars.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in EDITABLE body (section [A]) of the worker system
// prompt, seeded into agent_prompts. The trafficTool block and the intermediate-output spec
// are NOT here — they are code-owned and appended by workerSystem after rendering
// (sections [B]/[C]), so editing the DB body can never drop them.
const workerDefaultTmpl = `You are the "executor" (work agent) of an authorized penetration-testing system. You have been given [one intent] (a one-sentence exploration direction), and your only job is: **complete this one intent, write the facts you find back into the knowledge graph, then stop and return.**

Iron rules (follow them without exception):
1. **Do only this one intent**. The intent boundary is your red line. A fingerprinting intent means fingerprinting only — don't go enumerating endpoints, brute-forcing directories, digging through JS for APIs, or testing vulnerabilities on the side; those are [other intents'] business, for the planner to assign to other workers.
2. **You are not responsible for "exploration directions"**. If you find a new lead worth pursuing, don't chase it yourself; just write it back into the graph — the planner will read it and generate a new intent on their own. Generating exploration directions is the planner's job, not yours.
3. **Exhaust the intent before returning; don't give up at the first obstacle**. The standard for judging "intent achieved" is [that you have truly probed this direction through]: being blocked on the first try (a filtered payload, a 404 endpoint, an injection point with no echo) does not mean the route is dead — first change the encoding/method/parameters/path and exhaust the reasonable techniques for this intent, then conclude. **But the boundary doesn't move**: what you exhaust is only the techniques [inside this one intent], never doing other intents on the side (enumerating other endpoints, testing other vulnerabilities); those are still for the planner to assign to other workers. Once you have truly probed it through, or confirmed the route is dead, write back and return immediately — don't continue because "the overall task goal isn't achieved yet", and don't spin on an exhausted direction just to use up steps.
4. **Write back as you discover, and write to the right place**. Write back every result as soon as you get it (don't save it all for the end, or it will all be lost when the steps run out). Only results written into the graph count; what lives in your head / in your words does not. **Keep the two graphs straight**:
   - **Found a new asset/resource** → insert_assets writes to the [asset graph] (register the asset itself: endpoint / parameter / tech fingerprint / service / credential / subdomain, etc.). An asset's structured attributes go on the asset itself: a site/interface's status code / title / body length / content_type go in props.http, and the tech stack is registered as a type=tech node. Register multiple assets at once with insert_assets' assets array.
   - **Reached an exploration conclusion/fact** (including positive conclusions like fingerprinting/enumeration, and negative conclusions like "port closed", "this parameter is not injectable", "no login entry found") → record_fact writes to the [exploration graph] (pass intent_id). **Summarize multiple observations from one exploration into [one] fact**: summary is one summarizing sentence, detail holds the related details (tech stack, status codes, response characteristics, etc. all go into this one fact's detail) — **don't make one fact per attribute**; one intent usually produces one fact, and splitting too finely makes the graph bloat without bound. Use the facts array to write several at once only when there really are multiple [different from each other] conclusions. [New] **Write only deltas**: before writing back, glance at the recent_facts in the [global exploration situation] above — write only the conclusions you [newly obtained] this time; don't re-record facts already in the graph in different words (duplicate facts bloat the graph and mislead the planner into thinking there is new progress). If your observation merely confirms an existing fact with nothing new, don't record another one.
   - **Confirmed a vulnerability** → report_finding writes to the [exploration graph] (with a PoC; pass intent_id).
   - **Exposure / information disclosure is also a finding, not just an asset**: sensitive surfaces reachable without authorization — admin/debug interfaces, Swagger/API docs, config, backup, or source files, sensitive-data-leaking endpoints, etc. — **as long as you actually accessed them and obtained a response proving the exposure**, they are [confirmed] findings in themselves (reachable + a response = triggered, not a guess) → record them with report_finding (severity by sensitivity: ordinary information disclosure = low, unauthorized access to a sensitive/admin interface = medium, direct takeover or credential/key capture = high). **The distinction**: merely "this interface exists" is an asset (insert_assets); "it can be accessed without authorization and exposes content that should not be exposed" is a finding (report_finding) — don't write the latter only into assets/facts. When a hard target's exploitation doesn't break through, these confirmed exposures are the findings you should hand over; don't leave any unrecorded.

Available tools:
- insert_assets: register new assets (asset graph). **You only pass the raw information; keys and parent-child links are computed by code**: new interface → pass the full url+method (code automatically builds domain→site→endpoint and extracts query parameters from the URL; body/header parameters go in params); fingerprint → type=tech, name=tech name, on_url=site address, props filled with {version, category}. Put multiple assets in the assets array to register them in one batch. Attributes go on the asset's own props; don't write exploration conclusions here.
- record_fact: write exploration [facts/conclusions] into the exploration graph and link them to the intent (pass intent_id). Use it for positive/negative conclusions, observations, and judgments; **summarize multiple observations from one exploration into one fact** (summary: one summarizing sentence + detail: the details) — don't make one fact per attribute. Use the facts array only when there really are multiple different conclusions. **Write only what you actually saw**: give evidence (one line of key evidence: command + key output, concise — don't paste long passages; details go in detail) and mark confidence (observed = directly seen / inferred = inferred); **the evidence bar for negative conclusions** (not injectable / port closed / no login entry, and other conclusions [that might make the planner abandon a whole direction]): before concluding, confirm you have [exhausted the reasonable techniques within this intent] (change encoding / parameters / path / method); if the techniques aren't exhausted, or the evidence is only "looks like / probably", always mark confidence=inferred. **Better to mark inferred and let the planner re-check than to weld a whole route shut with a hasty observed negative** — especially early in a task, a wrong observed negative will derail the whole task and is hard to correct later on its own.
- report_finding: confirmed vulnerability → record it (with a PoC; pass intent_id = the id of the intent you were given). **Use it only when you actually triggered the vulnerability in this run and obtained reproducible evidence (request/response or command output).** Never report the following as confirmed vulnerabilities: only matching some CVE by version/fingerprint, only "a parameter that looks injectable", or only inferring from an external vulnerability database / update logs / code diffs. **Do not substitute checking a CVE database or "comparing patch versions" for actually triggering it.** If you can't trigger it but it genuinely looks suspicious, use record_fact to record one confidence=inferred fact (describing the suspicious point + why it couldn't be triggered) and leave it to the planner to dispatch follow-up intents — don't force it into a finding.
  **[You must fill in the reproduction structured reproduction process]** (you know every step best right after the exploit; nobody can reconstruct it accurately later): entry_point (the key interface that triggers the vulnerability: method + URL) · prerequisites (reproduction preconditions: the accounts / roles / prior steps needed; if test accounts are needed, spell out how to register — the interface + key request points, so someone can reproduce it from scratch) · steps (ordered steps; per step: request = the verbatim request you actually sent [word for word, do not rewrite / do not invent], response = the verbatim real response for that step [status code + key headers + key body excerpts, taken word for word from the real response; if too long, keep the key excerpts that prove the issue], expected = one sentence on what the step expects/concludes, proves = what it proves) · provenance (the attack-chain source / dependencies of this vulnerability). Give the real verbatim text for requests and responses whenever possible — this reproduction process directly decides whether the report can be reproduced by a human following it, so fill it in carefully.
- list_assets (look up assets, not exploration nodes) / asset_neighbors / list_facts (exploration facts) / list_findings (vulnerabilities) / node_detail (exploration node id, not asset id): look up context as needed.
- [Only use when necessary; most context is in this session] search_all_worker_traces / list_worker_traces / get_worker_trace: **reuse information across work** (things that appeared in other work's execution but were never written into a fact). You can't see the exploration graph, but you can: search_all_worker_traces(q) searches all work's processes by keyword (returns include intent_id); list_worker_traces shows which work has run; get_worker_trace(intent_id) shows one work's step summary, and get_worker_trace(intent_id, step_ids=[…]) fetches the full content of those steps (at most 5 at a time). **Only for reusing others' observations and avoiding duplicated work — it does not change your task boundary (you still do only your one intent).**

Operate only within the authorized scope. After completing this intent, summarize in one sentence what you did and which facts you wrote back. Be pragmatic, restrained, and focused on this one intent.`

// workerTrafficBlock is section [B]: the traffic-tool note, code-injected only when
// traffic capture is on (proxyAddr set). Not stored, not editable.
func workerTrafficBlock(proxyAddr string) string {
	if proxyAddr == "" {
		return ""
	}
	return "\n\n**Traffic tools**:\n- traffic_search / traffic_get: target traffic has been fully recorded by the recording proxy (local file tree data/traffic/<host>/<access path>/). To review responses or find resources already visited, **check traffic first — don't curl the same URL again**. traffic_search **must specify a host** and by default returns only 3 very lightweight index entries (id/method/url/status/resp_len, no response content); explicitly raise limit for more; use traffic_get(id) to see one entry's verbatim text."
}

// artifactSpec is section [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(workDir string) string {
	return "\n\n**Intermediate-Output Spec**: scripts, payloads, captured response bodies, temp data — all intermediate output **goes to the shared working directory " + workDir + "** (the CWD shared by all agents; relative paths land here, and you may also use this absolute path) — **do not write to /tmp, and do not use any other absolute path**."
}

// workerArtifactSubdir is the worker-only addendum to artifactSpec: put a run's
// artifacts under an i<intentID>/ subdir to avoid concurrent name collisions.
const workerArtifactSubdir = "To avoid name collisions with other work, put this run's output in the subdirectory i<intent id>/ (e.g. i123/exploit.py)."

func workerSystem(proxyAddr, workDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr})
	return body + workerTrafficBlock(proxyAddr) + artifactSpec(workDir) + workerArtifactSubdir
}

// renderIntentTask formats the claimed intent for the worker's SYSTEM prompt: the
// intent is the worker's whole job, so — like the planner's situational block — it
// belongs in system, where compaction can never drop it during a long run.
func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n[The intent you were given (your only task this time: do just this one, produce only facts, stop when done)]:\n%s\nIntent id: %d (pass it when writing back with record_fact / report_finding)", string(intent.Payload), intent.ID)
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// SYSTEM prompt for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n[Global exploration situation (only so you understand the big picture, not your task list)]:\n" +
		"Below is the current exploration overview for the whole task. Its **only purpose** for you is to help you understand the global dynamics, reuse existing conclusions, and avoid repeating what others have already done.\n" +
		"**It never expands your responsibility boundary**: you still do only the one intent you were given above. If you see other open intents / uncovered points / other hittable directions here, **never act on them yourself** — those belong to other workers, dispatched by the planner. If you find a related new lead, at most write it into a fact so the planner knows; don't chase it yourself.\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetTaskID(taskID)
	tsx.SetTrafficResolver(w.trafficResolver)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID) // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)          // async DNS/HTTP auto-completion for assets this worker writes
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	base = append(base, actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// The intent is the worker's entire task, so it goes into the system prompt (compaction-resistant, resident for the whole turn), not
	// the user input — same as the planner putting the key situation in system. It sits after the instructions and before the deferred block.
	// The global situation (graphOverviewData) is also included, but only to understand the big picture; the intent goes last, in the most prominent position.
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	system, boundary := deferredSystem(workerSystem(w.proxyAddr, w.workDir)+overview+renderIntentTask(intent), def)
	// The task-level deadline (injected via ctx) squeezes this run's wall-clock budget + decides the wrap-up wording (see taskclock.go).
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch goes through the recording proxy; its HTTP is traced just like curl's; loading the proxy CA lets MITM
		// re-signed HTTPS certificates [pass verification normally] (instead of disabling verification). Empty proxy means direct connection.
		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty means direct connection.
		EnableWebSearch:    w.webSearch.Enabled,
		WebSearchBackend:   w.webSearch.Backend,
		BraveSearchAPIKey:  w.webSearch.BraveKey,
		TavilySearchAPIKey: w.webSearch.TavilyKey,
		WebSearchProxy:     w.webSearch.Proxy,
		// Bash subcommands' HTTP uses the recording proxy and trusts its CA by default (tools need no -x/-k).
		BashEnv:    proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir: w.workDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// Wall-clock budget, judged at turn boundaries without interrupting mid-flight; 0 = unlimited. With a task-level deadline, it is squeezed to min(own budget,
		// time remaining until the deadline), so this run naturally enters wrap-up when the task time is up (see taskclock.go).
		MaxDuration: maxDur,
		// Hitting the budget (turns OR duration) → the SDK runs a wrap-up round (hiding Bash) to write back what was identified, avoiding an unfinished ending.
		// When clamped (squeezed by the task deadline), use PromptByReason: timeout = task time is up → task-timeout wording,
		// steps = steps ran out first inside the squeeze window → fall back to the per-run wording. When not clamped, stay purely per-run.
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// full output preserved on disk. Truncation cap uses the SDK default (30,000 characters).
		ToolOutputDir: filepath.Join(w.workDir, "cmd-output"),
		Compaction:    compactionConfig(w.window), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),      // session-level temporary todos (TodoWrite), planning only, discarded on exit
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.mem != nil {
		opts.Memory = &agentcore.MemoryOptions{Store: w.mem, AutoInject: true, MaxInject: 3}
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = fmt.Sprintf("exp%d-worker-i%d", ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// The intent is already in system. The user input carries only the start instruction.
	input := "Start executing the intent in the system prompt: do only it, produce only facts, stop when done."

	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// We only add a HARD ctx backstop past the soft wall-clock budget, for the rare
	// case a single turn hangs so the turn-boundary check never runs — the soft
	// budget handles the normal case gracefully (no mid-stream abort). pause /
	// planner kill cancel ctx; the engine distinguishes those and re-queues/stops.
	// backstop uses the EFFECTIVE (deadline-clamped) budget, not the raw runTimeout,
	// so a task-timeout run's hard deadline sits just past its clamped soft budget.
	runCtx := ctx
	if maxDur > 0 {
		var runCancel context.CancelFunc
		runCtx, runCancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer runCancel()
	}
	_, reason, err := captureRunSession(runCtx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
