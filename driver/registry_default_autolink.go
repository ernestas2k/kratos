// Copyright © 2026 Refurbed Marketplace GmbH
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"context"
	"slices"
	"strings"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x"
)

// Only domains the provider runs itself because elsewhere an admin can reassign a mailbox and email_verified proves nothing
var autoLinkDomains = map[string][]string{
	oidc.ProviderTypeGoogle: {"gmail.com", "googlemail.com"},
	oidc.ProviderTypeApple:  {"icloud.com", "me.com", "mac.com"},
}

func AutoLinkConflictPolicy(reg Registry) oidc.ConflictingIdentityPolicy {
	return func(ctx context.Context, existingIdentity, _ *identity.Identity, provider oidc.Provider, claims *oidc.Claims) oidc.ConflictingIdentityVerdict {
		log := reg.Logger()
		if provider != nil && provider.Config() != nil {
			log = log.WithField("provider", provider.Config().ID)
		}
		if existingIdentity != nil {
			log = log.WithField("identity_id", existingIdentity.ID)
		}
		reject := func(reason string) oidc.ConflictingIdentityVerdict {
			log.WithField("verdict", "reject").Info(reason)
			return oidc.ConflictingIdentityVerdictReject
		}
		merge := func() oidc.ConflictingIdentityVerdict {
			log.WithField("verdict", "merge").Info("Linked a social sign-in to an existing account.")
			return oidc.ConflictingIdentityVerdictMerge
		}

		if provider == nil || existingIdentity == nil || claims == nil {
			return reject("The sign-in did not provide a provider, an identity and claims.")
		}

		config := provider.Config()
		if config == nil || config.AccountLinkingMode != oidc.AccountLinkingModeAutomatic {
			return reject("The provider is not configured for automatic account linking.")
		}

		log = log.WithField("subject", claims.Subject)

		if !claims.EmailVerified {
			return reject("The provider did not report the email address as verified.")
		}

		if !existingIdentity.IsActive() {
			return reject("The identity is not active.")
		}

		email := x.NormalizeEmailIdentifier(claims.Email)
		local, mailDomain, found := strings.Cut(email, "@")
		if !found || local == "" || mailDomain == "" {
			return reject("The provider did not send a usable email address.")
		}

		log = log.WithField("claimed_mail_domain", mailDomain).
			WithSensitiveField("claimed_email_address", email)
		if !slices.Contains(autoLinkDomains[config.Provider], mailDomain) {
			return reject("The mail domain is not operated by the provider.")
		}

		if count, err := reg.IdentityManager().CountActiveMultiFactorCredentials(ctx, existingIdentity); err != nil {
			return reject("The identity's multi factor credentials could not be counted.")
		} else if count > 0 {
			return reject("The identity has an active second factor.")
		}

		// Saving an identity without its loaded addresses deletes them.
		if len(existingIdentity.VerifiableAddresses) == 0 {
			return reject("The identity's verifiable addresses were not loaded.")
		}

		for _, address := range existingIdentity.VerifiableAddresses {
			if address.Via != identity.AddressTypeEmail || !address.Verified {
				continue
			}
			if x.NormalizeEmailIdentifier(address.Value) == email {
				return merge()
			}
		}

		return reject("The identity has no verified address matching the claimed one.")
	}
}
