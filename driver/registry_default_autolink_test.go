// Copyright © 2026 Refurbed Marketplace GmbH
// SPDX-License-Identifier: Apache-2.0

package driver_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x"
	"github.com/ory/x/sqlxx"
)

func verdictName(v oidc.ConflictingIdentityVerdict) string {
	switch v {
	case oidc.ConflictingIdentityVerdictMerge:
		return "merge"
	case oidc.ConflictingIdentityVerdictReject:
		return "reject"
	default:
		return "unknown"
	}
}

func TestAutoLinkConflictPolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
	policy := driver.AutoLinkConflictPolicy(reg)
	reg.ActiveCredentialsCounterStrategies(ctx)

	newProvider := func(providerType, linkingMode string) oidc.Provider {
		config := &oidc.Configuration{
			Provider:           providerType,
			ID:                 providerType + "-web",
			ClientID:           "client",
			ClientSecret:       "secret",
			AccountLinkingMode: linkingMode,
		}
		if providerType == oidc.ProviderTypeApple {
			return oidc.NewProviderApple(config, reg)
		}
		return oidc.NewProviderGoogle(config, reg)
	}

	google := newProvider(oidc.ProviderTypeGoogle, oidc.AccountLinkingModeAutomatic)
	apple := newProvider(oidc.ProviderTypeApple, oidc.AccountLinkingModeAutomatic)

	identityWith := func(address string, verified bool) *identity.Identity {
		return &identity.Identity{
			State: identity.StateActive,
			Credentials: map[identity.CredentialsType]identity.Credentials{
				identity.CredentialsTypePassword: {
					Type:        identity.CredentialsTypePassword,
					Identifiers: []string{address},
					Config:      sqlxx.JSONRawMessage(`{"hashed_password":"$2a$10$abcdefghijklmnopqrstuv"}`),
				},
			},
			VerifiableAddresses: []identity.VerifiableAddress{{
				Value:    address,
				Verified: verified,
				Via:      identity.AddressTypeEmail,
			}},
		}
	}

	withCredential := func(i *identity.Identity, ct identity.CredentialsType, config string) *identity.Identity {
		i.Credentials[ct] = identity.Credentials{
			Type:        ct,
			Identifiers: []string{"dev@gmail.com"},
			Config:      sqlxx.JSONRawMessage(config),
		}
		return i
	}

	claimsFor := func(email string, emailVerified bool, subject string) *oidc.Claims {
		return &oidc.Claims{
			Subject:       subject,
			Email:         email,
			EmailVerified: x.ConvertibleBoolean(emailVerified),
		}
	}

	validClaims := claimsFor("dev@gmail.com", true, "sub-1")

	for _, tc := range []struct {
		name     string
		provider oidc.Provider
		existing *identity.Identity
		claims   *oidc.Claims
		expected oidc.ConflictingIdentityVerdict
	}{
		{
			name:     "merges a verified address the existing identity holds verified",
			provider: google,
			existing: identityWith("dev@gmail.com", true),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictMerge,
		},
		{
			name:     "merges googlemail.com, which google also operates",
			provider: google,
			existing: identityWith("dev@googlemail.com", true),
			claims:   claimsFor("dev@googlemail.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictMerge,
		},
		{
			name:     "normalizes both addresses before comparing",
			provider: google,
			existing: identityWith("Dev@Gmail.com", true),
			claims:   claimsFor("  DEV@GMAIL.COM ", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictMerge,
		},
		{
			name:     "merges an apple address on a domain apple operates",
			provider: apple,
			existing: identityWith("dev@icloud.com", true),
			claims:   claimsFor("dev@icloud.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictMerge,
		},
		{
			name:     "merges when a later address is the matching verified one",
			provider: google,
			existing: func() *identity.Identity {
				i := identityWith("other@gmail.com", true)
				i.VerifiableAddresses = append(i.VerifiableAddresses, identity.VerifiableAddress{
					Value: "dev@gmail.com", Verified: true, Via: identity.AddressTypeEmail,
				})
				return i
			}(),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictMerge,
		},
		{
			name:     "rejects a domain operated by the other provider",
			provider: google,
			existing: identityWith("dev@icloud.com", true),
			claims:   claimsFor("dev@icloud.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects a google domain presented by apple",
			provider: apple,
			existing: identityWith("dev@gmail.com", true),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when the provider does not opt in",
			provider: newProvider(oidc.ProviderTypeGoogle, oidc.AccountLinkingModeVerifyWithExistingCredential),
			existing: identityWith("dev@gmail.com", true),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when the provider has no linking mode set",
			provider: newProvider(oidc.ProviderTypeGoogle, ""),
			existing: identityWith("dev@gmail.com", true),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an inactive identity",
			provider: google,
			existing: func() *identity.Identity {
				i := identityWith("dev@gmail.com", true)
				i.State = identity.StateInactive
				return i
			}(),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when the identity expects a time-based second factor",
			provider: google,
			existing: withCredential(identityWith("dev@gmail.com", true), identity.CredentialsTypeTOTP,
				`{"totp_url":"otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"}`),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when the identity expects a lookup secret",
			provider: google,
			existing: withCredential(identityWith("dev@gmail.com", true), identity.CredentialsTypeLookup,
				`{"recovery_codes":[{"code":"key-1"}]}`),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when the provider did not verify the address",
			provider: google,
			existing: identityWith("dev@gmail.com", true),
			claims:   claimsFor("dev@gmail.com", false, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an address on a domain the provider does not operate",
			provider: google,
			existing: identityWith("dev@company.com", true),
			claims:   claimsFor("dev@company.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an address that only looks like a provider domain",
			provider: google,
			existing: identityWith("dev@notgmail.com", true),
			claims:   claimsFor("dev@notgmail.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an address with no domain",
			provider: google,
			existing: identityWith("gmail.com", true),
			claims:   claimsFor("gmail.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an address with no local part",
			provider: google,
			existing: identityWith("@gmail.com", true),
			claims:   claimsFor("@gmail.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an address with nothing after the at sign",
			provider: google,
			existing: identityWith("dev@", true),
			claims:   claimsFor("dev@", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when the existing identity holds the address unverified",
			provider: google,
			existing: identityWith("dev@gmail.com", false),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when the matching address is not an email address",
			provider: google,
			existing: func() *identity.Identity {
				i := identityWith("dev@gmail.com", true)
				i.VerifiableAddresses[0].Via = "sms"
				return i
			}(),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects when only a different address is verified",
			provider: google,
			existing: func() *identity.Identity {
				i := identityWith("someone.else@gmail.com", true)
				i.VerifiableAddresses = append(i.VerifiableAddresses, identity.VerifiableAddress{
					Value: "dev@gmail.com", Verified: false, Via: identity.AddressTypeEmail,
				})
				return i
			}(),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an identity whose addresses were never loaded",
			provider: google,
			existing: func() *identity.Identity {
				i := identityWith("dev@gmail.com", true)
				i.VerifiableAddresses = nil
				return i
			}(),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an address whose local part hides a second at sign",
			provider: google,
			existing: identityWith("attacker@evil.com@gmail.com", true),
			claims:   claimsFor("attacker@evil.com@gmail.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects an apple private relay address, which stays a separate account",
			provider: apple,
			existing: identityWith("abc123@privaterelay.appleid.com", true),
			claims:   claimsFor("abc123@privaterelay.appleid.com", true, "sub-1"),
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "skips addresses that are not verified email and keeps looking",
			provider: google,
			existing: func() *identity.Identity {
				i := identityWith("dev@gmail.com", true)
				i.VerifiableAddresses = append([]identity.VerifiableAddress{
					{Value: "+4915112345678", Verified: true, Via: "sms"},
					{Value: "old@gmail.com", Verified: false, Via: identity.AddressTypeEmail},
				}, i.VerifiableAddresses...)
				return i
			}(),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictMerge,
		},
		{
			name:     "rejects without an existing identity",
			provider: google,
			existing: nil,
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects without claims",
			provider: google,
			existing: identityWith("dev@gmail.com", true),
			claims:   nil,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
		{
			name:     "rejects without a provider",
			provider: nil,
			existing: identityWith("dev@gmail.com", true),
			claims:   validClaims,
			expected: oidc.ConflictingIdentityVerdictReject,
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			t.Parallel()

			got := policy(ctx, tc.existing, nil, tc.provider, tc.claims)
			assert.Equal(t, tc.expected, got, "got %s, want %s", verdictName(got), verdictName(tc.expected))
		})
	}
}

func TestOIDCStrategyIsBuiltWithTheAutoLinkPolicy(t *testing.T) {
	t.Parallel()

	_, reg := pkg.NewVeryFastRegistryWithoutDB(t)

	strategy, err := reg.AllLoginStrategies().Strategy(identity.CredentialsTypeOIDC)
	require.NoError(t, err)

	oidcStrategy, ok := strategy.(*oidc.Strategy)
	require.True(t, ok, "the oidc login strategy is not an *oidc.Strategy")

	policy := reflect.ValueOf(oidcStrategy).Elem().FieldByName("conflictingIdentityPolicy")
	assert.True(t, policy.IsValid(), "oidc.Strategy no longer has a conflictingIdentityPolicy field")
	assert.False(t, policy.IsNil(),
		"the oidc strategy was built without a conflicting identity policy, so automatic account linking is off")
}
