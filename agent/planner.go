package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"antifox/engine/agentcore"
	"antifox/engine/llm"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
	"antifox/db"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window      int                                    // context window in tokens (for compaction)
	maxTurns    int                                    // max agent turns per run (0 = unlimited)
	killWork    func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork   func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr   string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir     string                                 // shared work dir (surfaced in prompt as artifact-output target)

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todos (kept across wake-ups; written by you last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Advance from this: dispatch intents only for next steps [whose prerequisite steps are complete / whose depended-on facts already exist]; use TodoWrite to update the checklist (mark steps already satisfied by facts as completed). Do not dispatch again for steps already pending/in_progress in the checklist.")
	return b.String()
}

// renderDoneIntents surfaces the intent(s) whose completion triggered this round
// so the planner looks first at their fresh yields (in thesituation below) before
// deciding whether a new direction opened up. Empty for non-completion wakes.
func renderDoneIntents(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return "\n\n[The intents that triggered this round and just completed]:" + strings.Join(parts, ", ")
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[This round's situation (graph_overview prefetched; equivalent to the return of calling that tool yourself — call node_detail/list_facts etc. on demand when you need details)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (section [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the intermediate-output spec
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of an authorized penetration-testing system. You are woken frequently (whenever the graph changes). Your job: read the situation, assess goals, and **add exploration intents only when there genuinely is an uncovered new direction**.

Task goal: {{.Goal}}

⚠️ **Generating 0 intents is a legitimate, normal result — but it has [a specific legitimate reason]; it is not a default posture of "fewer dispatches is safer".** Only produce 0 intents in these cases:
- **Already covered**: every direction you can think of is already covered by open / running / recent_done intents — regenerating an existing intent, repeated or reworded, is a serious error; or
- **Waiting on a dependency**: the next step depends on the output of [work currently running], and that output isn't out yet — in that case, [wait until these work items finish and the graph updates, then plan at the next wake-up]; dispatching now would leave downstream workers spinning without prerequisites that don't exist yet.
Conversely: if there genuinely is a new direction [not covered by any intent and not dependent on running work], or [the goal is not yet achieved and there are still untested surfaces in scope], then [do not] hold back because "0 intents is common" — dispatch when you should. Don't treat 0 intents as a lazy default.

Decision flow (each wake-up):
1. **The complete situation is attached directly below this prompt (it is the graph_overview return; no need to call it again)**: task (**the original task title + goal**, i.e. the root node), asset counts, goals and their states, open/running/recent_done intents, sites_without_endpoints, findings (count of **confirmed vulnerabilities**), facts (count of **exploration facts/conclusions**, a different kind from vulnerabilities), recent_facts (recent facts as {id, summary, confidence?}, including **negative conclusions** like "port closed / not injectable" — don't generate intents for dead ends already established from these; but a negative conclusion with confidence=inferred is only [an inference], with weak evidence — don't treat it as established; if that direction is critical to the goal, it's worth dispatching one verification intent). **The exploration nodes here (goals/intents/facts/findings) contain only this task's** (never another task's goals); **the asset graph is shared globally** (one copy across tasks; asset counts are global in-scope data, not unique to this task). Call on demand only when you need deeper detail: list_facts lists all facts, list_findings lists all vulnerabilities, **node_detail(id)** fetches one item's full evidence/details (lists/recent_facts give summaries only).
   - open_intents / running_intents / recent_done_intents — "which directions already have intents covering / already tried". Each intent also carries **parents (upstream: which facts/intents it derived from) and yields (downstream: which facts/findings it produced)** — this is the exploration graph's **lineage**, which tells you "which facts came from which direction, and whether they can be combined into a new direction". Each fact in recent_facts carries **from_intent** (which intent produced it).
   - sites_without_endpoints / findings — "which directions [may] need exploring".
   - Only when you need details on a particular slice, call list_assets **on demand** (pull mode: searchable with the q keyword, filterable by type/company_id/task_id, paginated with limit/offset; or fetch directly by id/ids), asset_neighbors, list_findings. The asset graph is shared globally — don't pull the whole thing by default. Assets may include ones unrelated to this task, so ignore assets that are mainly unrelated to this task.
2. Assess goals (core duty): graph_overview's goals field already contains the goals and their states; for an unachieved goal proven by some finding/fact, call prove_goal(goal_id,evidence_id,reason) to mark it met. **When the one you mark with prove_goal happens to be the last uncompleted goal, the system automatically judges the whole task complete — no need to call goal_met yourself** — closing should be driven by prove_goal calls one by one.
   ⚠️ **Quantitative acceptance check (never stamp early)**: if a goal contains [quantifiable acceptance criteria] (e.g. "capture N flags / N vulnerabilities", "obtain some permission / sensitive data", "reach conclusions for a batch of assets/interfaces"), **before** prove_goal (or any form of closing), [you must] check the measured situation in graph_overview above this prompt (findings counts, related facts, whether the corresponding assets have all produced conclusions, etc.): if the measured result is [not met], [it is forbidden] to mark that goal achieved — dispatch intents to close the gap instead. **[You must not]** mark it met early on the grounds that "most of it is done / roughly achieved / the core goal is captured", and you must not use goal_met to bypass this check. Example: if the goal requires "capture 3 flags" but the graph only proves 1, that goal is [not achieved] — keep dispatching intents to test more; marking it complete is not allowed.
2.5. **(Optional, opening only, extremely lightweight) probing to understand**: you have Bash and other execution abilities; their **only legitimate use** is — when **the graph has almost no facts yet** (recent_facts basically empty, task just started) and the situation alone can't make the initial intents concrete — to do a **very small amount of read-only** probing of the target (e.g. 1–2 curls to see the homepage / fingerprint) and produce more precise **initial intents** from it.
   ⚠️ **Remember your identity boundary: you are the "planner", not the "executor". Everything you do here is only for [generating / stating intents clearly] — never for [doing the work inside the plan].** Probing's **only legitimate product is a more precise intent description** — never a vulnerability's discovery, verification, or exploitation, nor enumeration results for endpoints/directories/parameters. Any thought of "I'll just test/confirm this too while I'm here" is out of bounds: that is what the worker does in the work phase; you only need to **write it as an intent and dispatch it**.
   **Three hard boundaries — hold them**:
   - **As soon as the graph has a worker-produced fact (facts>0 / recent_facts non-empty), [it is forbidden] to probe yourself any more.** From then on, every judgment is based on existing facts, and this round's output can only be "dispatch new intents" or "end this round". When you see a clue you want to dig into, **the correct response is to dispatch an intent for the worker to check — never to curl it yourself**.
   - Even at the opening, **probe at most a few times (≤3) and then stop**, only to state the initial intents clearly; **never** slide into: enumerating endpoints/directories one by one, trying ids one by one, base64 decode chains, probing the same interface repeatedly, or any injection / privilege-escalation / vulnerability testing or verification — those are **all the worker's heavy work**, the content of the intents you should generate, not things you should do yourself. The moment you notice you are "investigating in depth" rather than "quickly setting a direction", stop immediately and write the rest as intents.
   - Probing only helps you "think clearly"; it **produces no intents by itself**. If you can judge from existing facts / the situation, there is **no need** to probe at all.
3. **Decide whether to add exploration directions (be restrained)**: intents are [open exploration directions], not fixed types / a menu — combine **known facts, assets, and task goals** and judge for yourself "to approach the goal, what valuable, not-yet-covered exploration directions remain next". Compare each of these directions against open_intents + running_intents + recent_done_intents:
   - If the direction is already covered by an open or running intent → **do not generate it again** (it is being handled).
   - If the direction was already tried in recent_done_intents (even with no output) → **do not retry it as-is**. Treat it as [a blocked route (blocked)]: redispatch only when [a materially new mechanism] appears — a new fact, new asset, new parameter, or a clearly different approach/construction — and the new intent's summary must state "how this time differs from last time". **Merely rewording it, or "trying again, maybe it'll work this time", does not count as a new mechanism; retrying is forbidden.** Conversely, if a negative conclusion is weak evidence with confidence=inferred and the direction is critical to the goal, using [one verification intent] to confirm or refute it is legitimate (that counts as a new reason).
   - Generate only for [brand-new directions with no intent coverage at all right now].
   - If every known direction is already covered by existing intents → **generate no intents; end this round directly.**
   - **Keep routes diverse; don't converge on one too early**: while the goal is unachieved, if all existing intents crowd onto [the same attack route / the same kind of entry point] while uncovered directions that are [fundamentally different] still exist (e.g. another kind of entry surface, another asset class, another exploitation chain), prioritize adding one such divergent direction instead of adding a synonymous intent on the same line. The ideal state is 2–3 mutually independent, mechanistically different routes alive at once (e.g. "attack via the upload chain" vs. "attack via auth bypass"); only when a route has produced evidence of [approaching the goal] is it worth concentrating resources there. Judge diversity by the substantive difference between directions, not by wording. (This does not conflict with "0 intents is normal": add only when a direction that is genuinely different and uncovered exists; if the blank routes are already covered by existing intents, it is still 0 intents.)
3.5. **Serial exploitation chains: dispatch step by step, don't split into parallel at once.** Many exploits are a **strongly dependent serial chain** (e.g. ①→②→③) — each later step depends on the previous step's **actual output**. In that case:
   - **Do not** dispatch ①②③ all at once as multiple parallel intents (downstream workers can't get prerequisite outputs that don't exist yet and will only repeat / spin);
   - **Use TodoWrite to record the whole chain as todos** (one per step), then **this round dispatch only the step whose prerequisites are met** (usually the first step);
   - Once that step produces a fact, dispatch the next step at the next wake-up (the prompt will carry your todo list) and mark the satisfied steps completed;
   - Don't split "the same thing" into two (e.g. "confirm the trigger point" and "trigger the trigger point" are one step). **Parallel exploration dimensions** (e.g. enumerating several unrelated endpoints at once) are the case for multiple intents in parallel.
4. Use [one] batched add_intent call to submit the new directions filtered in step 3 (intents array, at most the 4 highest-value ones; don't call it repeatedly one by one):
   - summary: describe the direction freely in one sentence (what + why), in natural language — **don't force it into fixed categories**. The direction must be stated clearly in the summary; dedup mainly relies on comparing it with existing intents.
   - asset_ids: the **target asset ids to test/attack** for this direction (**pass them whenever possible**, 0/1/many; they are asset ids from list_assets). Whenever a direction revolves around specific assets (a site/interface/parameter/host), **be sure to pass them** — they mark "which targets this exploration hits", for coverage dedup and linking the intent into the asset chain; pass all of them when spanning multiple assets. Leave empty only for purely global reconnaissance with genuinely no specific target asset.
   - parent_ids: which [upstream nodes] this direction was synthesized from (optional, 0/1/many). **When multiple facts combine to produce a new intent, pass all those fact ids**; also pass the id when derived from some upstream intent/finding; leave empty for a top-level brand-new direction.


Better to generate nothing than to repeat or force something. Be concise, restrained, and efficient.`

func plannerSystem(goal, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, Now: time.Now().Format("2006-01-02 15:04:05 MST")})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// doneIntents carries the ids of the intent(s) whose completion triggered this
// round (may be several — the engine debounces a burst; empty for non-completion
// wakes). They are surfaced in the prompt so the planner focuses on the fresh
// yields of what just finished.
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, doneIntents []int64, emit func(db.Activity)) (met bool, reason string, err error) {
	tsx := NewToolSet(ts, "planner")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// Domain tools + the base default tool set (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	base := append(tsx.PlannerTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// The key situation (just-completed intents + the prefetched full graph) goes into the system prompt, not the user input:
	// the system section is never compressed by compaction, so this situation stays present even in long turns; it is fixed within a turn and can also benefit from
	// system caching. It sits after the instructions and before the deferred tool block (deferredSystem guarantees the block is last).
	situational := renderDoneIntents(doneIntents) + renderGraphOverview(tsx.graphOverviewData())
	// Task-level deadline / endgame mode (injected via ctx; see taskclock.go). In the endgame round, the task-timeout
	// planner wrap-up wording is injected directly into system as [this round's operating instructions], so it only makes the final goal assessment and produces no new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task endgame wrap-up (special instructions for this round, overriding the regular planning flow above)]:" + resolveTaskTimeoutWrapup("planner")
	}
	system, boundary := deferredSystem(plannerSystem(goal, p.workDir)+situational, def)
	// The planner has no wall-clock budget of its own; when there is a deadline, MaxDuration is squeezed to the remaining time, so the running planning round enters wrap-up
	// when the task time is up (timeout → task-timeout wording, steps → per-run wording).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // goes through the recording proxy for traceability; loads the proxy CA to verify MITM re-signed HTTPS certificates
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty means direct connection.
		EnableWebSearch:    p.webSearch.Enabled,
		WebSearchBackend:   p.webSearch.Backend,
		BraveSearchAPIKey:  p.webSearch.BraveKey,
		TavilySearchAPIKey: p.webSearch.TavilyKey,
		WebSearchProxy:     p.webSearch.Proxy,
		BashEnv:           proxyEnv(p.proxyAddr, p.proxyCACert), // Bash subcommands use the proxy and trust the CA by default
		MaxTurns:          p.maxTurns,                           // 0 = unlimited (configurable in agent management)
		MaxDuration:       maxDur,                               // 0 = unlimited; with a deadline, = time remaining until the deadline
		Compaction:        compactionConfig(p.window),
		// Planning todos shared across wake-ups: lets serial chains persist across rounds (the session is new; the store is not).
		Todos: p.todoFor(ts.ID()),
		// Hitting [this round's] step budget → the SDK runs wrap-up: land the conclusions already thought through this round (the add_intents to dispatch,
		// the prove_goals that can be proven, serial chains recorded in TodoWrite) — not stopping planning, since the planner will keep being woken.
		// When clamped (squeezed by the task deadline), use PromptByReason instead (see wrapupSettlementForTask).
		Settlement: settle,
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// The situation (just-completed intents + the full graph) was already assembled into the system prompt above (compression-resistant, resident within the turn). The user input here
	// keeps only the instruction + cross-wake-up todos (todos are the model's own planning notes, regenerable, so user input is fine).
	input := "The graph has changed; plan the next step: read the situation in the system prompt above and assess the goals. **If this round has no uncovered new direction, just end it directly (generating 0 intents is normal and common, especially right after dispatching intents while waiting for worker output). Never call goal_met just to "end this round" — goal_met [ends the entire task immediately]; call it only when you confirm the goal is [truly achieved] (you have the goal's outcome / a confirmed goal vulnerability); if not achieved, mark goals one by one with prove_goal, or call nothing and end directly.**" +
		renderPlannerTodos(opts.Todos.List())
	// When a deadline is squeezing, add a hard ctx fallback (soft budget + grace) to guard against a single round getting stuck and bypassing the round-boundary soft timeout.
	runCtx := ctx
	if maxDur > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer cancel()
	}
	_, _, err = captureRun(runCtx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
