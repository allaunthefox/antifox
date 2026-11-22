package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "antifox/engine/tool"

	"antifox/knowledge"
)

// SetKnowledgeStore wires the knowledge-base service so search_knowledge /
// list_knowledge_categories are active. nil = the tools report "not enabled".
func (t *ToolSet) SetKnowledgeStore(kb *knowledge.Service) { t.kb = kb }

// search_knowledge — semantic (or keyword-fallback) retrieval over the two-layer
// knowledge base: global common knowledge + this task's uploaded background.
func (t *ToolSet) searchKnowledge() actool.CoreTool {
	return readTool("search_knowledge",
		"Search the knowledge base: global general knowledge (vulnerability database / 0days / techniques / methodology) + this task's own material (scoring rules / authorization scope / targets / checklists). Describe in natural language what you are looking for; the most relevant knowledge snippets are returned. Actively search relevant knowledge while working to guide method selection and assessment criteria.",
		obj(map[string]any{
			"query": str("The question or topic to search for, described in natural language"),
			"top_k": intp("Number of results to return, default 5"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
				TopK  int    `json:"top_k"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query must not be empty"), nil
			}
			if t.kb == nil {
				return actool.Text("Knowledge base is not enabled."), nil
			}
			if a.TopK <= 0 {
				a.TopK = 5
			}
			hits, mode, err := t.kb.SearchAndLog(ctx, a.Query, t.taskID, a.TopK, t.worker)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("Search failed: %v", err)), nil
			}
			if len(hits) == 0 {
				return actool.Text("No relevant content found in the knowledge base."), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Search mode: %s, %d hits:\n", mode, len(hits))
			for i, h := range hits {
				scope := "Global"
				if h.Scope == "task" {
					scope = "Task-specific"
				}
				fmt.Fprintf(&b, "\n--- Result %d (similarity %.0f%%, %s) ---\n[%s] %s\n%s\n",
					i+1, h.Score*100, scope, h.Category, h.Title, strings.TrimSpace(h.Content))
			}
			return actool.Text(b.String()), nil
		})
}

// list_knowledge_categories — enumerate categories so the agent can browse before
// a targeted search_knowledge call.
func (t *ToolSet) listKnowledgeCategories() actool.CoreTool {
	return readTool("list_knowledge_categories",
		"List the knowledge base's existing categories (global + current task). See what categories exist first, then use search_knowledge for targeted retrieval.",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			if t.kb == nil {
				return actool.Text("Knowledge base is not enabled."), nil
			}
			cats, err := t.kb.Categories(t.taskID)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("Read failed: %v", err)), nil
			}
			if len(cats) == 0 {
				return actool.Text("The knowledge base has no categories yet."), nil
			}
			return actool.Text("Knowledge base categories:\n- " + strings.Join(cats, "\n- ")), nil
		})
}
