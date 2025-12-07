package yara

import (
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

// parseStrings extracts string definitions from YARA rule
func parseStrings(section string, strings map[string][]byte) {
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

		// Handle quoted strings
		if hasPrefix(value, "\"") && hasSuffix(value, "\"") {
			strings[name] = []byte(value[1 : len(value)-1])
		}
		// Handle hex strings
		if hasPrefix(value, "{") && hasSuffix(value, "}") {
			hexStr := replaceAll(value[1:len(value)-1], " ", "")
			if decoded, err := hex.DecodeString(hexStr); err == nil {
				strings[name] = decoded
			}
		}
	}
}

// executeRule executes a parsed YARA rule against data
func executeRule(rule ParsedRule, data []byte) []yarav1alpha1.ScanMatch {
	var matches []yarav1alpha1.ScanMatch

	// Simple pattern matching for defined strings
	for name, pattern := range rule.Strings {
		offsets := findAllOccurrences(data, pattern)
		if len(offsets) > 0 {
			var matchStrings []yarav1alpha1.MatchString
			for _, offset := range offsets {
				matchData := pattern
				if len(matchData) > 64 {
					matchData = matchData[:64]
				}
				matchStrings = append(matchStrings, yarav1alpha1.MatchString{
					Name:   name,
					Offset: int64(offset),
					Length: len(pattern),
					Data:   hex.EncodeToString(matchData),
				})
			}

			matches = append(matches, yarav1alpha1.ScanMatch{
				Rule:    rule.Name,
				Tags:    rule.Tags,
				Strings: matchStrings,
				Meta:    rule.Meta,
			})
			break // One match per rule is enough
		}
	}

	// Handle "any of them" condition
	if containsString(rule.Condition, "any of them") && len(rule.Strings) > 0 {
		for name, pattern := range rule.Strings {
			offsets := findAllOccurrences(data, pattern)
			if len(offsets) > 0 {
				var matchStrings []yarav1alpha1.MatchString
				for _, offset := range offsets {
					matchData := pattern
					if len(matchData) > 64 {
						matchData = matchData[:64]
					}
					matchStrings = append(matchStrings, yarav1alpha1.MatchString{
						Name:   name,
						Offset: int64(offset),
						Length: len(pattern),
						Data:   hex.EncodeToString(matchData),
					})
				}

				matches = append(matches, yarav1alpha1.ScanMatch{
					Rule:    rule.Name,
					Tags:    rule.Tags,
					Strings: matchStrings,
					Meta:    rule.Meta,
				})
				break
			}
		}
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
