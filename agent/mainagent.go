package agent

import (
	"context"
	"fmt"

	"antifox/engine/agentcore"
	"antifox/engine/llm"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
	"antifox/db"
)

// MainAgent is the thin human-interface orchestrator (docs §4.2 / §7). The human
// chats with it; it observes (read tools), and steers by injecting hints
// (→planner) or direct high-priority intents (→frontier). It does NOT run the
// autonomous intent-generation loop (that is the planner's job).
type MainAgent struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	proxyAddr   string            // recording proxy for WebFetch (empty = direct)
	proxyCACert string            // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	workDir     string            // shared work dir (surfaced in prompt as artifact-output target)
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// mainAgentDefaultTmpl is the built-in EDITABLE body (section [A]) of the main agent
// prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the intermediate-output spec tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `You are the "main agent" of an authorized penetration-testing system, the interface to the human operator. You do not explore yourself, and you do not autonomously generate intents in sequence (that is the planner's job). Your responsibilities:

1. Observe: use graph_overview / list_findings / list_facts / list_assets / get_worker_output to answer the human's questions about current progress.
2. Record vulnerabilities (important — don't miss any): for every vulnerability the worker has verified and confirmed, or you have reviewed and confirmed, **call report_finding immediately, one call per vulnerability, to store it** — filling in vulnclass (vulnerability name/type), severity (critical|high|medium|low; critical = can directly cause total system/data compromise, e.g. RCE, unauthorized arbitrary file reads that yield keys/credentials, privilege bypasses that allow account takeover), summary (including the affected target), evidence (reproducible requests/commands/responses — the verbatim real PoC text), and asset_ids for affected assets that have an id; **and fill in the reproduction structured reproduction process whenever possible** (entry_point: the entry interface / prerequisites: preconditions, including how to register test accounts / steps: each step's real request + expectation + proof / provenance: source) — take requests verbatim from the worker transcript / what was actually executed; do not rewrite them, so the report can be reproduced from scratch by a human. **Once confirmed, record it — do not ask permission, and do not just list vulnerabilities in your reply** — only vulnerabilities recorded via report_finding reach the findings page / exploration graph / reports; writing them in a reply without recording them = wasted work. Check list_findings first for what is already recorded, to avoid duplicates. Never report guesses based only on version/CVE matching or that merely "look exploitable" as confirmed vulnerabilities. **Exposure / information-disclosure findings also count as findings**: sensitive surfaces the worker has proven to be reachable without authorization (admin/debug interfaces, Swagger/API docs, exposed configs, backups, or source code, sensitive-data-leaking endpoints, etc., with response evidence actually obtained) should likewise be reported one by one via report_finding (severity by sensitivity: ordinary information disclosure = low, unauthorized access to a sensitive/admin interface = medium, direct takeover or credential capture = high) — don't treat them as mere assets/facts. **When the user asks you to "summarize current findings", or when a task wraps up / pauses**: store each qualifying vulnerability and confirmed exposure the worker has written back into the graph, one by one (check list_findings/list_facts first for what exists, and deduplicate) — even for hard targets where exploitation didn't break through, hand over these confirmed exposures/risks; don't just list them in your reply.
3. Steer (turn the human's intent into system action):
   - The human wants to "change direction / emphasize a vulnerability class / focus on an area" → write a hint with add_hint (the planner will read it next time).
   - The human wants to "test a specific target right now" → inject one high-priority intent directly with add_intent (priority 8-10).
4. Reply briefly in plain language, explaining what you did and which vulnerabilities you recorded.

Current task goal: {{.Goal}}

Do not invent findings; record and answer only from the real data returned by tools and verified evidence.`

func mainAgentSystem(goal, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal})
	return body + artifactSpec(workDir)
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify func()) (string, error) {
	tsx := NewToolSet(ts, "human")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetNotify(notify) // add_hint wakes this task's planner (debounced)
	// Domain tools + the base default tool set (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	base := append(tsx.MainAgentTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // goes through the recording proxy for traceability; loads the proxy CA to verify MITM re-signed HTTPS certificates
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty means direct connection.
		EnableWebSearch:    m.webSearch.Enabled,
		WebSearchBackend:   m.webSearch.Backend,
		BraveSearchAPIKey:  m.webSearch.BraveKey,
		TavilySearchAPIKey: m.webSearch.TavilyKey,
		WebSearchProxy:     m.webSearch.Proxy,
		BashEnv:           proxyEnv(m.proxyAddr, m.proxyCACert), // Bash subcommands use the proxy and trust the CA by default
		MaxTurns:          m.maxTurns,                           // 0 = unlimited (configurable in agent management)
		Compaction:        compactionConfig(m.window),           // long chats stay within the window
		Todos:             actool.NewTodoStore(),                // session-level temporary todos (TodoWrite), planning only, discarded on exit
		// Hitting the budget (steps) → the SDK runs wrap-up: output one progress summary sentence to the user. Prompt and wrap-up turns are editable in the backend (default: 5 turns).
		Settlement: wrapupSettlement("mainagent", nil),
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per task
		opts.Transcript = m.tx
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
	}
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}
