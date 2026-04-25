package iam

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testConditionKeys = map[string]bool{
	"test:key":            true,
	"aws:securetransport": true,
	"s3:max-keys":         true,
	"aws:currenttime":     true,
}

func mustParsePolicy(t *testing.T, policyJSON string) *Policy {
	t.Helper()
	policy, err := ParsePolicyJSON(policyJSON, Options{AllowedConditionKeys: testConditionKeys})
	require.NoError(t, err)
	return policy
}

func TestPolicyAuthorize_AllowsMatchingStatement(t *testing.T) {
	policy := mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::example-bucket/private/*"
		}
	}`)

	err := policy.Authorize(Request{
		Action:   "S3:GETOBJECT",
		Resource: "arn:aws:s3:::example-bucket/private/a/b.txt",
	})
	require.NoError(t, err)
}

func TestPolicyAuthorize_DeniesImplicitly(t *testing.T) {
	policy := mustParsePolicy(t, `{
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::example-bucket/public/*"
		}
	}`)

	err := policy.Authorize(Request{
		Action:   "s3:PutObject",
		Resource: "arn:aws:s3:::example-bucket/public/a.txt",
	})
	require.ErrorIs(t, err, ErrImplicitDeny)
}

func TestPolicyAuthorize_ExplicitDenyOverridesAllow(t *testing.T) {
	policy := mustParsePolicy(t, `{
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:*",
				"Resource": "arn:aws:s3:::example-bucket/*"
			},
			{
				"Effect": "Deny",
				"Action": "s3:DeleteObject",
				"Resource": "arn:aws:s3:::example-bucket/protected/*"
			}
		]
	}`)

	err := policy.Authorize(Request{
		Action:   "s3:DeleteObject",
		Resource: "arn:aws:s3:::example-bucket/protected/a.txt",
	})
	require.ErrorIs(t, err, ErrExplicitDeny)
}

func TestPolicyAuthorize_NotActionAndNotResource(t *testing.T) {
	policy := mustParsePolicy(t, `{
		"Statement": [
			{
				"Effect": "Allow",
				"NotAction": "s3:DeleteObject",
				"NotResource": "arn:aws:s3:::example-bucket/private/*"
			}
		]
	}`)

	require.NoError(t, policy.Authorize(Request{
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3:::example-bucket/public/a.txt",
	}))
	require.ErrorIs(t, policy.Authorize(Request{
		Action:   "s3:DeleteObject",
		Resource: "arn:aws:s3:::example-bucket/public/a.txt",
	}), ErrImplicitDeny)
	require.ErrorIs(t, policy.Authorize(Request{
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3:::example-bucket/private/a.txt",
	}), ErrImplicitDeny)
}

func TestParsePolicyJSON_RejectsUnsupportedOrUnsafePolicies(t *testing.T) {
	tests := []struct {
		name       string
		policyJSON string
	}{
		{
			name:       "empty",
			policyJSON: "",
		},
		{
			name: "principal",
			policyJSON: `{
				"Statement": {
					"Effect": "Allow",
					"Principal": "*",
					"Action": "s3:GetObject",
					"Resource": "*"
				}
			}`,
		},
		{
			name: "unknown condition key",
			policyJSON: `{
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "*",
					"Condition": {"StringEquals": {"s3:ExistingObjectTag/class": "public"}}
				}
			}`,
		},
		{
			name: "policy variable",
			policyJSON: `{
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::example-bucket/${aws:username}/*"
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicyJSON(tt.policyJSON, Options{AllowedConditionKeys: testConditionKeys})
			require.ErrorIs(t, err, ErrInvalidPolicy)
		})
	}
}

func TestPolicyAuthorize_ConditionOperators(t *testing.T) {
	tests := []struct {
		name      string
		operator  string
		key       string
		expected  any
		context   Context
		wantAllow bool
	}{
		{
			name:      "StringEquals",
			operator:  "StringEquals",
			key:       "test:key",
			expected:  "alpha",
			context:   Context{"test:key": {"alpha"}},
			wantAllow: true,
		},
		{
			name:      "StringNotEquals",
			operator:  "StringNotEquals",
			key:       "test:key",
			expected:  "alpha",
			context:   Context{"test:key": {"beta"}},
			wantAllow: true,
		},
		{
			name:      "StringLike",
			operator:  "StringLike",
			key:       "test:key",
			expected:  "tenant/*",
			context:   Context{"test:key": {"tenant/a.txt"}},
			wantAllow: true,
		},
		{
			name:      "StringNotLike",
			operator:  "StringNotLike",
			key:       "test:key",
			expected:  "private/*",
			context:   Context{"test:key": {"public/a.txt"}},
			wantAllow: true,
		},
		{
			name:      "Bool",
			operator:  "Bool",
			key:       "aws:SecureTransport",
			expected:  true,
			context:   Context{"aws:securetransport": {"true"}},
			wantAllow: true,
		},
		{
			name:      "Null true",
			operator:  "Null",
			key:       "test:key",
			expected:  true,
			context:   Context{},
			wantAllow: true,
		},
		{
			name:      "Null false",
			operator:  "Null",
			key:       "test:key",
			expected:  false,
			context:   Context{"test:key": {"present"}},
			wantAllow: true,
		},
		{
			name:      "NumericEquals",
			operator:  "NumericEquals",
			key:       "s3:max-keys",
			expected:  25,
			context:   Context{"s3:max-keys": {"25"}},
			wantAllow: true,
		},
		{
			name:      "NumericNotEquals",
			operator:  "NumericNotEquals",
			key:       "s3:max-keys",
			expected:  25,
			context:   Context{"s3:max-keys": {"26"}},
			wantAllow: true,
		},
		{
			name:      "NumericLessThan",
			operator:  "NumericLessThan",
			key:       "s3:max-keys",
			expected:  100,
			context:   Context{"s3:max-keys": {"99"}},
			wantAllow: true,
		},
		{
			name:      "NumericLessThanEquals",
			operator:  "NumericLessThanEquals",
			key:       "s3:max-keys",
			expected:  100,
			context:   Context{"s3:max-keys": {"100"}},
			wantAllow: true,
		},
		{
			name:      "NumericGreaterThan",
			operator:  "NumericGreaterThan",
			key:       "s3:max-keys",
			expected:  10,
			context:   Context{"s3:max-keys": {"11"}},
			wantAllow: true,
		},
		{
			name:      "NumericGreaterThanEquals",
			operator:  "NumericGreaterThanEquals",
			key:       "s3:max-keys",
			expected:  10,
			context:   Context{"s3:max-keys": {"10"}},
			wantAllow: true,
		},
		{
			name:      "DateEquals",
			operator:  "DateEquals",
			key:       "aws:CurrentTime",
			expected:  "2026-04-25T10:00:00Z",
			context:   Context{"aws:currenttime": {"2026-04-25T10:00:00Z"}},
			wantAllow: true,
		},
		{
			name:      "DateNotEquals",
			operator:  "DateNotEquals",
			key:       "aws:CurrentTime",
			expected:  "2026-04-25T10:00:00Z",
			context:   Context{"aws:currenttime": {"2026-04-25T10:01:00Z"}},
			wantAllow: true,
		},
		{
			name:      "DateLessThan",
			operator:  "DateLessThan",
			key:       "aws:CurrentTime",
			expected:  "2026-04-25T10:01:00Z",
			context:   Context{"aws:currenttime": {"2026-04-25T10:00:00Z"}},
			wantAllow: true,
		},
		{
			name:      "DateLessThanEquals",
			operator:  "DateLessThanEquals",
			key:       "aws:CurrentTime",
			expected:  "2026-04-25T10:00:00Z",
			context:   Context{"aws:currenttime": {"2026-04-25T10:00:00Z"}},
			wantAllow: true,
		},
		{
			name:      "DateGreaterThan",
			operator:  "DateGreaterThan",
			key:       "aws:CurrentTime",
			expected:  "2026-04-25T09:59:00Z",
			context:   Context{"aws:currenttime": {"2026-04-25T10:00:00Z"}},
			wantAllow: true,
		},
		{
			name:      "DateGreaterThanEquals",
			operator:  "DateGreaterThanEquals",
			key:       "aws:CurrentTime",
			expected:  "2026-04-25T10:00:00Z",
			context:   Context{"aws:currenttime": {"2026-04-25T10:00:00Z"}},
			wantAllow: true,
		},
		{
			name:      "condition miss denies",
			operator:  "StringEquals",
			key:       "test:key",
			expected:  "alpha",
			context:   Context{"test:key": {"beta"}},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyJSON := fmt.Sprintf(`{
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "*",
					"Condition": {%q: {%q: %s}}
				}
			}`, tt.operator, tt.key, mustMarshalConditionValue(t, tt.expected))
			policy := mustParsePolicy(t, policyJSON)

			err := policy.Authorize(Request{
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3:::example-bucket/a.txt",
				Context:  tt.context,
			})
			if tt.wantAllow {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrImplicitDeny)
			}
		})
	}
}

func mustMarshalConditionValue(t *testing.T, value any) string {
	t.Helper()
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("%q", v)
	case bool:
		return strconvBool(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func strconvBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func FuzzParsePolicyJSON(f *testing.F) {
	f.Add(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	f.Add(`{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`)
	f.Add(`not-json`)

	for _, seed := range []string{
		`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}}`,
		`{"Statement":{"Effect":"Allow","NotAction":"s3:DeleteObject","NotResource":"arn:aws:s3:::bucket/private/*"}}`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		policy, err := ParsePolicyJSON(input, Options{AllowedConditionKeys: testConditionKeys})
		if err != nil {
			assert.True(t, errors.Is(err, ErrInvalidPolicy))
			return
		}
		_ = policy.Authorize(Request{
			Action:   "s3:GetObject",
			Resource: "arn:aws:s3:::bucket/key",
			Context: Context{
				"aws:securetransport": {"true"},
				"test:key":            {"value"},
				"s3:max-keys":         {"10"},
				"aws:currenttime":     {"2026-04-25T10:00:00Z"},
			},
		})
	})
}
