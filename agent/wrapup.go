package agent

import (
	"strings"

	"antifox/engine/harness"
)

// Wrap-up prompt (wrap-up / settlement prompt): when an agent is terminated because of [step budget exhausted (MaxTurns)] or
//  [timeout (run_seconds/MaxDuration)]  the SDK's settlement phase injects this prompt,
// so the agent first stores what it has identified but not yet written back, then outputs one summary sentence, instead of ending unfinished.
//
// Each agent's wrap-up prompt can be overridden in the backend as needed (stored in agents.wrapup_prompt); when empty, the built-in default here is used.
// Built-in default. Only the [prompt body] is editable; which tools are disabled and how many turns wrap-up itself gets are fixed code policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, indexed by agent key. The worker reuses the historically hardcoded settleWrapUpPrompt
// (defined in worker.go); planner/mainagent each have their own version; unmatched keys (custom agents) fall back to the generic one.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: built-in defaults for each agent's wrap-up-phase [itself] turn budget (overridable in the backend with >0).
// The worker's write-back may take several turns (record_fact/insert_assets), so it gets 4; the rest get 5. Unmatched keys use genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    4,
	"planner":   5,
	"mainagent": 5,
}

const genericWrapupTurns = 5

const plannerWrapUpDefault = "Your planning steps for this round are about to run out — note that only [this round] ends; the system will wake you again later as the situation changes to keep planning, so this is not the end of the task and you do not need to wrap up the whole plan here. Land the conclusions you have already thought through this round — don't let this round go to waste — but also [do not force intents together just for the sake of wrapping up] (0 intents this round is still a completely normal result): (1) if you have already identified an exploration direction [that should be dispatched now] , submit it in one batched add_intent call (don't hold back what you've already decided); (2) for a goal proven achieved by some finding/fact, call prove_goal to mark it met (don't miss any); (3) if you identify a serial exploitation chain that needs step-by-step work, record it with TodoWrite so the next wake-up can dispatch from it. When done, end this round directly; no summary text is needed."

const mainAgentWrapUpDefault = "Your steps are about to run out and this interaction is about to end. Do not start any new exploration/operation. Please summarize the current progress, key conclusions, and suggested next steps to the user **in one standalone plain-text sentence**."

const genericWrapUpDefault = "You are about to be terminated because your budget is exhausted. First write back the results you have completed but not yet stored, then summarize what you did and the key conclusions you reached **in one standalone plain-text sentence** (this sentence will be shown as the result of this run)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// ---------- Task-level timeout wrap-up wording (see docs/任务级超时与收尾设计.md)----------
//
// It is [two sets]: per-run means "your budget for this one run is used up"; task timeout means
// "the whole task has reached its time and is about to end". The meanings are often opposite (especially for the planner: per-run says "don't stop, keep planning",
// while task timeout says "time is up, stop planning and make the final assessment"). Only configured for worker/planner.

// WrapupTaskTimeoutOverride / …TurnsOverride: DB overrides for the task-timeout wrap-up wording and turn counts
// (wired to agents.task_timeout_wrapup_prompt / _max_turns, worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The whole task has reached its timeout limit and is about to end** (this is not your budget for this run — the entire exploration has run out of time). This is your last chance: (1) store [all] of the content you have identified but not yet written back — new assets via insert_assets, exploration conclusions/facts via record_fact, confirmed vulnerabilities via report_finding; (2) do not start any new commands/probes; (3) **finally, in one standalone plain-text sentence**, summarize your key conclusions for this intent."

const plannerTaskTimeoutDefault = "**The whole task has reached its timeout limit and is about to end** (not this round — the entire task is terminating). Based on the current [all] facts and findings, make the final goal assessment: for goals proven achieved by evidence, call prove_goal to mark them met (don't miss any). **Do not generate any new intents** (intents dispatched now will no longer be executed). Once assessed, wrap up; no summary text is needed."

// TaskTimeoutWrapupDefault returns an agent's built-in default task-timeout wrap-up wording (for backend placeholders / restoring defaults).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // unconfigured (mainagent/chat) returns an empty string
}

// resolveTaskTimeoutWrapup: DB override (non-empty) > built-in default. An empty string means the agent has no task-timeout wording
// (not worker/planner), in which case the caller should fall back to the per-run wording.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // by default, keep using the per-run turn count
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  → this run is squeezed by the task deadline: Timeout wrap-up = task time is up → task-timeout wording;
//     MaxTurns wrap-up = steps ran out first inside the squeeze window with a few minutes left on the task → fall back to the per-run wording.
//   - clamped=false → the task still has plenty of time: both reasons use the per-run wording (i.e. it degrades to wrapupSettlement).
//
// The harness's PromptByReason picks by the [actual] reason on the spot at wrap-up, so there is no build-time mismatch.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // fallback (also what both reasons take when not clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // task time is up
				harness.ReasonMaxTurns: perRun, // steps ran out first, task still has time
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
