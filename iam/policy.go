package iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidPolicy = errors.New("invalid IAM policy")
	ErrExplicitDeny  = errors.New("explicit deny")
	ErrImplicitDeny  = errors.New("implicit deny")
)

type Context map[string][]string

type Request struct {
	Action   string
	Resource string
	Context  Context
}

type Options struct {
	AllowedConditionKeys map[string]bool
}

type Policy struct {
	statements []statement
}

type statement struct {
	sid          string
	effect       effect
	actionMode   matchMode
	actions      []wildcard
	resourceMode matchMode
	resources    []wildcard
	conditions   []condition
}

type effect int

const (
	effectAllow effect = iota + 1
	effectDeny
)

type matchMode int

const (
	matchPositive matchMode = iota + 1
	matchNegative
)

type condition struct {
	operator conditionOperator
	key      string
	values   []string
}

type conditionOperator struct {
	name     string
	family   conditionFamily
	negative bool
}

type conditionFamily int

const (
	conditionStringEquals conditionFamily = iota + 1
	conditionStringLike
	conditionBool
	conditionNull
	conditionNumericEquals
	conditionNumericLessThan
	conditionNumericLessThanEquals
	conditionNumericGreaterThan
	conditionNumericGreaterThanEquals
	conditionDateEquals
	conditionDateLessThan
	conditionDateLessThanEquals
	conditionDateGreaterThan
	conditionDateGreaterThanEquals
)

type wildcard struct {
	raw string
	re  *regexp.Regexp
}

func DenyAllPolicy() *Policy {
	return &Policy{}
}

func ParsePolicyJSON(policyJSON string, opts Options) (*Policy, error) {
	if strings.TrimSpace(policyJSON) == "" {
		return nil, invalidPolicy("policy JSON is empty")
	}
	if !utf8.ValidString(policyJSON) {
		return nil, invalidPolicy("policy JSON must be valid UTF-8")
	}

	dec := json.NewDecoder(strings.NewReader(policyJSON))
	dec.UseNumber()

	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, invalidPolicy("parse policy JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, invalidPolicy("policy JSON must contain a single object")
	}
	if raw == nil {
		return nil, invalidPolicy("policy JSON must be an object")
	}

	for key := range raw {
		switch key {
		case "Version", "Statement":
		default:
			return nil, invalidPolicy("unsupported top-level policy element %q", key)
		}
	}

	if versionRaw, ok := raw["Version"]; ok {
		var version string
		if err := json.Unmarshal(versionRaw, &version); err != nil {
			return nil, invalidPolicy("Version must be a string")
		}
		if version != "2012-10-17" && version != "2008-10-17" {
			return nil, invalidPolicy("unsupported policy Version %q", version)
		}
	}

	statementRaw, ok := raw["Statement"]
	if !ok {
		return nil, invalidPolicy("policy must include Statement")
	}

	rawStatements, err := parseStatementList(statementRaw)
	if err != nil {
		return nil, err
	}
	if len(rawStatements) == 0 {
		return nil, invalidPolicy("policy must include at least one statement")
	}

	allowedConditionKeys := canonicalConditionKeySet(opts.AllowedConditionKeys)
	policy := &Policy{
		statements: make([]statement, 0, len(rawStatements)),
	}
	for i, rawStatement := range rawStatements {
		stmt, err := compileStatement(rawStatement, allowedConditionKeys)
		if err != nil {
			return nil, invalidPolicy("statement %d: %w", i, err)
		}
		policy.statements = append(policy.statements, stmt)
	}

	return policy, nil
}

func (p *Policy) Authorize(req Request) error {
	if p == nil {
		return ErrImplicitDeny
	}

	allowed := false
	for _, stmt := range p.statements {
		if !stmt.matches(req) {
			continue
		}
		if stmt.effect == effectDeny {
			return ErrExplicitDeny
		}
		allowed = true
	}

	if !allowed {
		return ErrImplicitDeny
	}
	return nil
}

func (s statement) matches(req Request) bool {
	if !matchesByMode(s.actionMode, s.actions, req.Action, true) {
		return false
	}
	if !matchesByMode(s.resourceMode, s.resources, req.Resource, false) {
		return false
	}
	for _, cond := range s.conditions {
		if !cond.matches(req.Context) {
			return false
		}
	}
	return true
}

func matchesByMode(mode matchMode, patterns []wildcard, value string, action bool) bool {
	matched := false
	for _, pattern := range patterns {
		if pattern.matches(value, action) {
			matched = true
			break
		}
	}
	if mode == matchNegative {
		return !matched
	}
	return matched
}

func (c condition) matches(ctx Context) bool {
	values, found := ctx.values(c.key)

	if c.operator.family == conditionNull {
		wantNull := false
		for _, value := range c.values {
			parsed, err := strconv.ParseBool(strings.ToLower(value))
			if err == nil && parsed {
				wantNull = true
				break
			}
		}
		isNull := !found || len(values) == 0
		return isNull == wantNull
	}

	if !found || len(values) == 0 {
		return c.operator.negative
	}

	anyMatch := false
	for _, actual := range values {
		for _, expected := range c.values {
			if c.valueMatches(actual, expected) {
				anyMatch = true
				break
			}
		}
		if anyMatch {
			break
		}
	}

	if c.operator.negative {
		return !anyMatch
	}
	return anyMatch
}

func (c condition) valueMatches(actual, expected string) bool {
	switch c.operator.family {
	case conditionStringEquals:
		return actual == expected
	case conditionStringLike:
		return mustWildcard(expected).matches(actual, false)
	case conditionBool:
		actualBool, actualErr := strconv.ParseBool(strings.ToLower(actual))
		expectedBool, expectedErr := strconv.ParseBool(strings.ToLower(expected))
		return actualErr == nil && expectedErr == nil && actualBool == expectedBool
	case conditionNumericEquals:
		actualNumber, expectedNumber, ok := parseNumbers(actual, expected)
		return ok && actualNumber == expectedNumber
	case conditionNumericLessThan:
		actualNumber, expectedNumber, ok := parseNumbers(actual, expected)
		return ok && actualNumber < expectedNumber
	case conditionNumericLessThanEquals:
		actualNumber, expectedNumber, ok := parseNumbers(actual, expected)
		return ok && actualNumber <= expectedNumber
	case conditionNumericGreaterThan:
		actualNumber, expectedNumber, ok := parseNumbers(actual, expected)
		return ok && actualNumber > expectedNumber
	case conditionNumericGreaterThanEquals:
		actualNumber, expectedNumber, ok := parseNumbers(actual, expected)
		return ok && actualNumber >= expectedNumber
	case conditionDateEquals:
		actualTime, expectedTime, ok := parseTimes(actual, expected)
		return ok && actualTime.Equal(expectedTime)
	case conditionDateLessThan:
		actualTime, expectedTime, ok := parseTimes(actual, expected)
		return ok && actualTime.Before(expectedTime)
	case conditionDateLessThanEquals:
		actualTime, expectedTime, ok := parseTimes(actual, expected)
		return ok && (actualTime.Before(expectedTime) || actualTime.Equal(expectedTime))
	case conditionDateGreaterThan:
		actualTime, expectedTime, ok := parseTimes(actual, expected)
		return ok && actualTime.After(expectedTime)
	case conditionDateGreaterThanEquals:
		actualTime, expectedTime, ok := parseTimes(actual, expected)
		return ok && (actualTime.After(expectedTime) || actualTime.Equal(expectedTime))
	default:
		return false
	}
}

func (c Context) values(key string) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	values, ok := c[canonicalConditionKey(key)]
	return values, ok
}

func parseNumbers(actual, expected string) (float64, float64, bool) {
	actualNumber, err := strconv.ParseFloat(actual, 64)
	if err != nil || math.IsNaN(actualNumber) || math.IsInf(actualNumber, 0) {
		return 0, 0, false
	}
	expectedNumber, err := strconv.ParseFloat(expected, 64)
	if err != nil || math.IsNaN(expectedNumber) || math.IsInf(expectedNumber, 0) {
		return 0, 0, false
	}
	return actualNumber, expectedNumber, true
}

func parseTimes(actual, expected string) (time.Time, time.Time, bool) {
	actualTime, err := parseIAMTime(actual)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	expectedTime, err := parseIAMTime(expected)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	return actualTime, expectedTime, true
}

func parseIAMTime(value string) (time.Time, error) {
	if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(unix, 0).UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	return time.Parse("2006-01-02T15:04:05Z", value)
}

func parseStatementList(raw json.RawMessage) ([]map[string]json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, invalidPolicy("Statement must not be empty")
	}

	var single map[string]json.RawMessage
	if raw[0] == '{' {
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, invalidPolicy("Statement must be an object or array")
		}
		return []map[string]json.RawMessage{single}, nil
	}

	var many []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, invalidPolicy("Statement must be an object or array")
	}
	return many, nil
}

func compileStatement(raw map[string]json.RawMessage, allowedConditionKeys map[string]bool) (statement, error) {
	if raw == nil {
		return statement{}, invalidPolicy("statement must be an object")
	}
	for key := range raw {
		switch key {
		case "Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition":
		case "Principal", "NotPrincipal":
			return statement{}, invalidPolicy("%s is not supported in identity policies", key)
		default:
			return statement{}, invalidPolicy("unsupported statement element %q", key)
		}
	}

	stmt := statement{}
	if sidRaw, ok := raw["Sid"]; ok {
		if err := json.Unmarshal(sidRaw, &stmt.sid); err != nil {
			return statement{}, invalidPolicy("Sid must be a string")
		}
	}

	effectRaw, ok := raw["Effect"]
	if !ok {
		return statement{}, invalidPolicy("Effect is required")
	}
	var effectValue string
	if err := json.Unmarshal(effectRaw, &effectValue); err != nil {
		return statement{}, invalidPolicy("Effect must be a string")
	}
	switch effectValue {
	case "Allow":
		stmt.effect = effectAllow
	case "Deny":
		stmt.effect = effectDeny
	default:
		return statement{}, invalidPolicy("Effect must be Allow or Deny")
	}

	actionRaw, hasAction := raw["Action"]
	notActionRaw, hasNotAction := raw["NotAction"]
	if hasAction == hasNotAction {
		return statement{}, invalidPolicy("exactly one of Action or NotAction is required")
	}
	actionValues, err := parseStringList(rawChoice(actionRaw, notActionRaw), "Action")
	if err != nil {
		return statement{}, err
	}
	stmt.actionMode = matchPositive
	if hasNotAction {
		stmt.actionMode = matchNegative
	}
	stmt.actions, err = compileWildcards(actionValues, true)
	if err != nil {
		return statement{}, err
	}

	resourceRaw, hasResource := raw["Resource"]
	notResourceRaw, hasNotResource := raw["NotResource"]
	if hasResource == hasNotResource {
		return statement{}, invalidPolicy("exactly one of Resource or NotResource is required")
	}
	resourceValues, err := parseStringList(rawChoice(resourceRaw, notResourceRaw), "Resource")
	if err != nil {
		return statement{}, err
	}
	stmt.resourceMode = matchPositive
	if hasNotResource {
		stmt.resourceMode = matchNegative
	}
	stmt.resources, err = compileWildcards(resourceValues, false)
	if err != nil {
		return statement{}, err
	}

	if conditionRaw, ok := raw["Condition"]; ok {
		stmt.conditions, err = parseConditions(conditionRaw, allowedConditionKeys)
		if err != nil {
			return statement{}, err
		}
	}

	return stmt, nil
}

func rawChoice(first, second json.RawMessage) json.RawMessage {
	if first != nil {
		return first
	}
	return second
}

func parseStringList(raw json.RawMessage, field string) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if strings.Contains(single, "${") {
			return nil, invalidPolicy("%s contains unsupported policy variable", field)
		}
		if single == "" {
			return nil, invalidPolicy("%s value must not be empty", field)
		}
		return []string{single}, nil
	}

	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, invalidPolicy("%s must be a string or array of strings", field)
	}
	if len(many) == 0 {
		return nil, invalidPolicy("%s must not be empty", field)
	}
	for _, value := range many {
		if strings.Contains(value, "${") {
			return nil, invalidPolicy("%s contains unsupported policy variable", field)
		}
		if value == "" {
			return nil, invalidPolicy("%s value must not be empty", field)
		}
	}
	return many, nil
}

func compileWildcards(values []string, action bool) ([]wildcard, error) {
	patterns := make([]wildcard, 0, len(values))
	for _, value := range values {
		if action {
			value = strings.ToLower(value)
		}
		pattern, err := compileWildcard(value)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func compileWildcard(value string) (wildcard, error) {
	re, err := regexp.Compile("^" + wildcardToRegex(value) + "$")
	if err != nil {
		return wildcard{}, invalidPolicy("invalid wildcard pattern %q: %w", value, err)
	}
	return wildcard{raw: value, re: re}, nil
}

func mustWildcard(value string) wildcard {
	w, err := compileWildcard(value)
	if err != nil {
		return wildcard{raw: value, re: regexp.MustCompile(`a\Ab`)}
	}
	return w
}

func (w wildcard) matches(value string, action bool) bool {
	if action {
		value = strings.ToLower(value)
	}
	return w.re.MatchString(value)
}

func wildcardToRegex(pattern string) string {
	var b strings.Builder
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

func parseConditions(raw json.RawMessage, allowedConditionKeys map[string]bool) ([]condition, error) {
	var byOperator map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byOperator); err != nil {
		return nil, invalidPolicy("Condition must be an object")
	}
	if len(byOperator) == 0 {
		return nil, invalidPolicy("Condition must not be empty")
	}

	var conditions []condition
	for operatorName, byKey := range byOperator {
		operator, err := parseConditionOperator(operatorName)
		if err != nil {
			return nil, err
		}
		if len(byKey) == 0 {
			return nil, invalidPolicy("Condition operator %s must include at least one key", operatorName)
		}
		for key, valueRaw := range byKey {
			canonicalKey := canonicalConditionKey(key)
			if !allowedConditionKeys[canonicalKey] {
				return nil, invalidPolicy("unsupported condition key %q", key)
			}
			values, err := parseConditionValues(valueRaw)
			if err != nil {
				return nil, invalidPolicy("condition key %q: %w", key, err)
			}
			conditions = append(conditions, condition{
				operator: operator,
				key:      canonicalKey,
				values:   values,
			})
		}
	}
	return conditions, nil
}

func parseConditionOperator(name string) (conditionOperator, error) {
	operator := conditionOperator{name: name}
	switch name {
	case "StringEquals":
		operator.family = conditionStringEquals
	case "StringNotEquals":
		operator.family = conditionStringEquals
		operator.negative = true
	case "StringLike":
		operator.family = conditionStringLike
	case "StringNotLike":
		operator.family = conditionStringLike
		operator.negative = true
	case "Bool":
		operator.family = conditionBool
	case "Null":
		operator.family = conditionNull
	case "NumericEquals":
		operator.family = conditionNumericEquals
	case "NumericNotEquals":
		operator.family = conditionNumericEquals
		operator.negative = true
	case "NumericLessThan":
		operator.family = conditionNumericLessThan
	case "NumericLessThanEquals":
		operator.family = conditionNumericLessThanEquals
	case "NumericGreaterThan":
		operator.family = conditionNumericGreaterThan
	case "NumericGreaterThanEquals":
		operator.family = conditionNumericGreaterThanEquals
	case "DateEquals":
		operator.family = conditionDateEquals
	case "DateNotEquals":
		operator.family = conditionDateEquals
		operator.negative = true
	case "DateLessThan":
		operator.family = conditionDateLessThan
	case "DateLessThanEquals":
		operator.family = conditionDateLessThanEquals
	case "DateGreaterThan":
		operator.family = conditionDateGreaterThan
	case "DateGreaterThanEquals":
		operator.family = conditionDateGreaterThanEquals
	default:
		return conditionOperator{}, invalidPolicy("unsupported condition operator %q", name)
	}
	return operator, nil
}

func parseConditionValues(raw json.RawMessage) ([]string, error) {
	var single any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&single); err != nil {
		return nil, invalidPolicy("invalid condition value: %w", err)
	}

	if list, ok := single.([]any); ok {
		if len(list) == 0 {
			return nil, invalidPolicy("condition value list must not be empty")
		}
		values := make([]string, 0, len(list))
		for _, value := range list {
			converted, err := conditionValueToString(value)
			if err != nil {
				return nil, err
			}
			values = append(values, converted)
		}
		return values, nil
	}

	value, err := conditionValueToString(single)
	if err != nil {
		return nil, err
	}
	return []string{value}, nil
}

func conditionValueToString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		if strings.Contains(v, "${") {
			return "", invalidPolicy("condition value contains unsupported policy variable")
		}
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case json.Number:
		return v.String(), nil
	default:
		return "", invalidPolicy("condition value must be a string, number, bool, or array of those")
	}
}

func canonicalConditionKeySet(keys map[string]bool) map[string]bool {
	out := make(map[string]bool, len(keys))
	for key, allowed := range keys {
		if allowed {
			out[canonicalConditionKey(key)] = true
		}
	}
	return out
}

func canonicalConditionKey(key string) string {
	return strings.ToLower(key)
}

func invalidPolicy(format string, args ...any) error {
	args = append([]any{ErrInvalidPolicy}, args...)
	return fmt.Errorf("%w: "+format, args...)
}
