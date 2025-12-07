package yara

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	yarav1alpha1 "github.com/yara-operator/yara-operator/api/v1alpha1"
)

// Scanner provides YARA scanning capabilities
type Scanner struct {
	mu sync.Mutex
}

// NewScanner creates a new YARA scanner
func NewScanner() *Scanner {
	return &Scanner{}
}

// ValidateRule validates a YARA rule syntax
func (s *Scanner) ValidateRule(ruleContent string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Basic validation - check for required sections
	if !strings.Contains(ruleContent, "rule ") {
		return fmt.Errorf("rule content must contain 'rule' keyword")
	}

	if !strings.Contains(ruleContent, "{") || !strings.Contains(ruleContent, "}") {
		return fmt.Errorf("rule content must contain rule body with braces")
	}

	if !strings.Contains(ruleContent, "condition:") {
		return fmt.Errorf("rule content must contain 'condition:' section")
	}

	// Count braces to ensure they're balanced
	openBraces := strings.Count(ruleContent, "{")
	closeBraces := strings.Count(ruleContent, "}")
	if openBraces != closeBraces {
		return fmt.Errorf("unbalanced braces in rule")
	}

	return nil
}

// ScanData scans data using provided YARA rules
func (s *Scanner) ScanData(data []byte, rules []string) ([]yarav1alpha1.ScanMatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var matches []yarav1alpha1.ScanMatch

	// Combine all rules
	combinedRules := strings.Join(rules, "\n\n")

	// Parse and execute rules using our embedded scanner
	parsedRules, err := parseRules(combinedRules)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}

	// Execute each rule against the data
	for _, rule := range parsedRules {
		ruleMatches := executeRule(rule, data)
		matches = append(matches, ruleMatches...)
	}

	return matches, nil
}

// ParsedRule represents a parsed YARA rule
type ParsedRule struct {
	Name      string
	Tags      []string
	Meta      map[string]string
	Strings   map[string][]byte
	Condition string
}

// parseRules parses YARA rules from content
func parseRules(content string) ([]ParsedRule, error) {
	var rules []ParsedRule

	// Split by "rule " to get individual rules
	parts := strings.Split(content, "rule ")

	for _, part := range parts[1:] { // Skip first empty part
		rule, err := parseRule("rule " + part)
		if err != nil {
			continue // Skip invalid rules
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRule parses a single YARA rule
func parseRule(content string) (ParsedRule, error) {
	rule := ParsedRule{
		Meta:    make(map[string]string),
		Strings: make(map[string][]byte),
	}

	// Extract rule name
	nameStart := strings.Index(content, "rule ") + 5
	nameEnd := strings.IndexAny(content[nameStart:], " :{")
	if nameEnd == -1 {
		return rule, fmt.Errorf("could not find rule name")
	}
	rule.Name = strings.TrimSpace(content[nameStart : nameStart+nameEnd])

	// Check for tags
	tagStart := strings.Index(content, ":")
	braceStart := strings.Index(content, "{")
	if tagStart != -1 && tagStart < braceStart {
		tagSection := content[tagStart+1 : braceStart]
		rule.Tags = strings.Fields(tagSection)
	}

	// Extract strings section
	stringsStart := strings.Index(content, "strings:")
	conditionStart := strings.Index(content, "condition:")

	if stringsStart != -1 && conditionStart != -1 {
		stringsSection := content[stringsStart+8 : conditionStart]
		parseStrings(stringsSection, rule.Strings)
	}

	// Extract condition
	if conditionStart != -1 {
		endBrace := strings.LastIndex(content, "}")
		if endBrace > conditionStart {
			rule.Condition = strings.TrimSpace(content[conditionStart+10 : endBrace])
		}
	}

	return rule, nil
}

// StringDef represents a parsed string definition with modifiers
type StringDef struct {
	Pattern  []byte
	NoCase   bool
	IsRegex  bool
	RegexStr string
}

// parseStrings extracts string definitions from YARA rule
func parseStrings(section string, strDefs map[string][]byte) {
	lines := splitLines(section)
	for _, line := range lines {
		line = trimSpace(line)
		if line == "" {
			continue
		}

		// Parse string definition: $name = "value" or $name = { hex }
		if !hasPrefix(line, "$") {
			continue
		}

		eqIdx := indexOf(line, "=")
		if eqIdx == -1 {
			continue
		}

		name := trimSpace(line[:eqIdx])
		value := trimSpace(line[eqIdx+1:])

		// Check for modifiers (nocase, wide, ascii, etc.)
		nocase := containsString(strings.ToLower(value), " nocase")

		// Handle quoted strings (with possible modifiers)
		if hasPrefix(value, "\"") {
			// Find closing quote
			closeQuote := -1
			for i := 1; i < len(value); i++ {
				if value[i] == '"' && (i == 1 || value[i-1] != '\\') {
					closeQuote = i
					break
				}
			}
			if closeQuote > 0 {
				strValue := value[1:closeQuote]
				// Handle escape sequences
				strValue = strings.ReplaceAll(strValue, "\\n", "\n")
				strValue = strings.ReplaceAll(strValue, "\\t", "\t")
				strValue = strings.ReplaceAll(strValue, "\\r", "\r")
				strValue = strings.ReplaceAll(strValue, "\\\"", "\"")
				strValue = strings.ReplaceAll(strValue, "\\\\", "\\")
				if nocase {
					// Store both upper and lower versions for nocase matching
					strDefs[name] = []byte(strings.ToLower(strValue))
					strDefs[name+"_upper"] = []byte(strings.ToUpper(strValue))
				} else {
					strDefs[name] = []byte(strValue)
				}
			}
		}
		// Handle regex patterns /pattern/
		if hasPrefix(value, "/") {
			closeSlash := strings.LastIndex(value, "/")
			if closeSlash > 0 {
				regexStr := value[1:closeSlash]
				// For simple regex, extract literal parts
				// This is a simplified approach - extract key literals from regex
				literals := extractLiteralsFromRegex(regexStr)
				for i, lit := range literals {
					if lit != "" {
						suffix := ""
						if i > 0 {
							suffix = fmt.Sprintf("_%d", i)
						}
						strDefs[name+suffix] = []byte(lit)
					}
				}
			}
		}
		// Handle hex strings
		if hasPrefix(value, "{") {
			closeIdx := indexOf(value, "}")
			if closeIdx > 0 {
				hexStr := replaceAll(value[1:closeIdx], " ", "")
				if decoded, err := hex.DecodeString(hexStr); err == nil {
					strDefs[name] = decoded
				}
			}
		}
	}
}

// extractLiteralsFromRegex extracts literal strings from a regex pattern
func extractLiteralsFromRegex(pattern string) []string {
	var literals []string
	var current strings.Builder

	// Simple extraction - get runs of literal characters
	inBracket := false
	escape := false

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]

		if escape {
			// Escaped character
			if c == 's' || c == 'd' || c == 'w' || c == 'S' || c == 'D' || c == 'W' {
				// Character class - flush current literal
				if current.Len() > 0 {
					literals = append(literals, current.String())
					current.Reset()
				}
			} else {
				current.WriteByte(c)
			}
			escape = false
			continue
		}

		switch c {
		case '\\':
			escape = true
		case '[':
			inBracket = true
			if current.Len() > 0 {
				literals = append(literals, current.String())
				current.Reset()
			}
		case ']':
			inBracket = false
		case '(', ')', '*', '+', '?', '{', '}', '|', '^', '$', '.':
			if !inBracket {
				if current.Len() > 0 {
					literals = append(literals, current.String())
					current.Reset()
				}
			}
		default:
			if !inBracket {
				current.WriteByte(c)
			}
		}
	}

	if current.Len() > 0 {
		literals = append(literals, current.String())
	}

	// Filter out very short literals
	var filtered []string
	for _, lit := range literals {
		if len(lit) >= 3 {
			filtered = append(filtered, lit)
		}
	}

	return filtered
}

// executeRule executes a parsed YARA rule against data
func executeRule(rule ParsedRule, data []byte) []yarav1alpha1.ScanMatch {
	var matches []yarav1alpha1.ScanMatch
	var allMatchStrings []yarav1alpha1.MatchString
	matchedNames := make(map[string]bool)

	// Convert data to lowercase for case-insensitive matching
	dataLower := bytes.ToLower(data)

	// Try matching each string definition
	for name, pattern := range rule.Strings {
		// Skip _upper variants - they're just for reference
		if strings.HasSuffix(name, "_upper") {
			continue
		}

		// Check for case-insensitive pattern (has _upper sibling)
		isNoCase := false
		if _, hasUpper := rule.Strings[name+"_upper"]; hasUpper {
			isNoCase = true
		}

		var offsets []int
		if isNoCase {
			// Case-insensitive: search lowercase pattern in lowercase data
			offsets = findAllOccurrences(dataLower, bytes.ToLower(pattern))
		} else {
			// Case-sensitive: search pattern in original data
			offsets = findAllOccurrences(data, pattern)
		}

		if len(offsets) > 0 && !matchedNames[name] {
			matchedNames[name] = true
			for _, offset := range offsets {
				// Get actual matched data from original
				matchLen := len(pattern)
				if offset+matchLen > len(data) {
					matchLen = len(data) - offset
				}
				matchData := data[offset : offset+matchLen]
				if len(matchData) > 64 {
					matchData = matchData[:64]
				}
				allMatchStrings = append(allMatchStrings, yarav1alpha1.MatchString{
					Name:   name,
					Offset: int64(offset),
					Length: len(pattern),
					Data:   hex.EncodeToString(matchData),
				})
				break // One match per string is enough
			}
		}
	}

	// Evaluate condition
	conditionMet := false

	if containsString(rule.Condition, "any of them") {
		// "any of them" - true if any string matched
		conditionMet = len(allMatchStrings) > 0
	} else if containsString(rule.Condition, "all of them") {
		// "all of them" - true only if all defined strings matched
		// Count unique string definitions (excluding _upper variants)
		definedCount := 0
		for name := range rule.Strings {
			if !strings.HasSuffix(name, "_upper") {
				definedCount++
			}
		}
		conditionMet = len(matchedNames) == definedCount && definedCount > 0
	} else {
		// Default: any match counts
		conditionMet = len(allMatchStrings) > 0
	}

	if conditionMet && len(allMatchStrings) > 0 {
		matches = append(matches, yarav1alpha1.ScanMatch{
			Rule:    rule.Name,
			Tags:    rule.Tags,
			Strings: allMatchStrings,
			Meta:    rule.Meta,
		})
	}

	return matches
}

// findAllOccurrences finds all occurrences of pattern in data
func findAllOccurrences(data, pattern []byte) []int {
	var offsets []int
	if len(pattern) == 0 || len(data) < len(pattern) {
		return offsets
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			offsets = append(offsets, i)
		}
	}

	return offsets
}

// Helper functions to avoid strings package in hot path
func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

func hasSuffix(s, suffix string) bool {
	return strings.HasSuffix(s, suffix)
}

func indexOf(s, substr string) int {
	return strings.Index(s, substr)
}

func replaceAll(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

