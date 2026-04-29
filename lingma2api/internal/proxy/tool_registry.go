package proxy

// ToolRegistry holds known Lingma built-in tools.
// Phase 1: empty — all tools are transparently passed through.
// Phase 3: populated with analyzed Lingma IDE tools.
type ToolRegistry struct {
	tools map[string]ToolDefinition
}

// ToolDefinition describes a Lingma built-in tool available for mapping.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// NewToolRegistry creates an empty tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]ToolDefinition),
	}
}

// Lookup returns the tool definition by name, or nil if not registered.
func (r *ToolRegistry) Lookup(name string) (*ToolDefinition, bool) {
	def, ok := r.tools[name]
	return &def, ok
}

// Register adds a tool definition to the registry.
func (r *ToolRegistry) Register(def ToolDefinition) {
	r.tools[def.Name] = def
}

// List returns all registered tool definitions.
func (r *ToolRegistry) List() []ToolDefinition {
	defs := make([]ToolDefinition, 0, len(r.tools))
	for _, def := range r.tools {
		defs = append(defs, def)
	}
	return defs
}
