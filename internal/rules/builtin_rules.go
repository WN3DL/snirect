package rules

// Built-in hardcoded rules have been decoupled.
// builtinRules is retained as an empty fallback for compatibility.
// All active routing rules are now loaded dynamically from rules.json.
var builtinRules = NewRules()