package plugin

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/smartcontractkit/smdkg/dkgocr/dkgocrtypes"
	"github.com/smartcontractkit/smdkg/internal/codec"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkg"
	"github.com/smartcontractkit/smdkg/internal/crypto/dkgtypes"
	"github.com/smartcontractkit/smdkg/internal/crypto/math"
)

// Reads the previous result package from the db if previousInstanceID is provided, otherwise returns nil.
func readPreviousResultPackage(ctx context.Context, db dkgocrtypes.ResultPackageDatabase, previousInstanceID *dkgocrtypes.InstanceID) (*ResultPackage, error) {
	// If no previous instance ID provided, return nil directly.
	if previousInstanceID == nil {
		return nil, nil
	}

	// Read the prior result package.
	priorResult, err := db.ReadResultPackage(ctx, *previousInstanceID)
	if err != nil {
		return nil, fmt.Errorf("Error occurred while reading prior result package from kv store: %w", err)
	}

	// Return error if no prior result found in the db in the resharing case.
	if priorResult == nil {
		return nil, fmt.Errorf("no prior result package found for instance ID %s", *previousInstanceID)
	}

	// Unmarshal the prior result package.
	resultPackage := &ResultPackage{}
	if err := resultPackage.UnmarshalBinary(priorResult.ReportWithResultPackage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal prior result package with instance ID %s: %w", *previousInstanceID, err)
	}

	return resultPackage, nil
}

// Creates a new DKG instance based on the provided parameters.
// If previousResultPackage is nil, a fresh dealing DKG instance will be created.
// Otherwise, a resharing DKG instance will be created based on previousResultPackage.
func newDKG(iid dkgtypes.InstanceID, curve math.Curve, dealers []dkgtypes.P256PublicKey, recipients []dkgtypes.P256PublicKey,
	f_D int, t_R int, keyring dkgtypes.P256Keyring, previousResultPackage *ResultPackage,
) (dkg.DKG, error) {
	if previousResultPackage == nil {
		// Create a fresh dealing DKG instance
		return dkg.NewInitialDKG(iid, curve, dealers, recipients, f_D, t_R, keyring)
	} else {
		// Check that the curve in the prior result matches the curve in config.
		if curve.Name() != previousResultPackage.Inner.Curve().Name() {
			return nil, fmt.Errorf("curve in config (%s) does not match curve in prior result package (%s)", curve.Name(), previousResultPackage.Inner.Curve().Name())
		}

		// Check that t_R in the prior result is greater than f_D in the new config.
		// Otherwise, the DKG security property is violated.
		if previousResultPackage.Config.T <= f_D {
			return nil, fmt.Errorf("t_R (%d) in prior result package is not greater than f_D (%d) in new config", previousResultPackage.Config.T, f_D)
		}

		// Check that the dealers' public keys in config match the recipients' public keys in the prior result.
		if len(dealers) != len(previousResultPackage.Config.RecipientPublicKeys) {
			return nil, fmt.Errorf("mismatch in number of dealers and prior recipients: %d vs %d", len(dealers), len(previousResultPackage.Config.RecipientPublicKeys))
		}
		for i := range dealers {
			if !bytes.Equal(dealers[i].Bytes(), previousResultPackage.Config.RecipientPublicKeys[i]) {
				return nil, fmt.Errorf("dealer public key at index %d does not match prior recipient public key", i)
			}
		}

		// Create a resharing DKG instance.
		dkg, err := dkg.NewResharingDKG(iid, dealers, recipients, f_D, t_R, keyring, previousResultPackage.Inner)
		if err != nil {
			return nil, fmt.Errorf("failed to create DKG instance for resharing: %w", err)
		}

		return dkg, nil
	}
}

// Generates a new initial dealing and serializes it as bytes to be broadcast to other dealers.
func deal(dkgInstance dkg.DKG, rand io.Reader) ([]byte, error) {
	dealing, err := dkgInstance.Deal(rand)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial dealing: %w", err)
	}

	// Serialize the dealing as an unverified dealing as payload in a blob
	marshaled, err := codec.Marshal(dealing.AsUnverifiedDealing())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal unverified initial dealing: %w", err)
	}

	return marshaled, nil
}

// Unmarshals and verifies an initial dealing received from a dealer.
func verifyInitialDealing(dkgInstance dkg.DKG, marshaled []byte, dealer int) (dkg.VerifiedInitialDealing, error) {
	unverifiedInitialDealing, err := codec.Unmarshal(marshaled, dkg.NewUnverifiedInitialDealing())
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal initial dealing: %w", err)
	}

	verifiedInitialDealing, err := dkgInstance.VerifyInitialDealing(unverifiedInitialDealing, dealer)
	if err != nil {
		return nil, fmt.Errorf("failed to verify initial dealing from dealer %d: %w", dealer, err)
	}

	return verifiedInitialDealing, nil
}

// Decrypts the decryption key shares from other dealers in the initial dealings and serializes them as bytes to be broadcast to other dealers.
func decryptDecryptionKeyShares(dkgInstance dkg.DKG, initialDealings initialDealings) ([]byte, error) {
	shares, err := dkgInstance.DecryptDecryptionKeyShares(initialDealings)
	if err != nil {
		return nil, err
	}

	ob, err := codec.Marshal(shares.AsUnverifiedShares())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal unverified decryption key shares: %w", err)
	}
	return ob, nil
}

// Unmarshals and verifies decryption key shares received from a dealer.
func verifyDecryptionKeyShares(dkgInstance dkg.DKG, initialDealings initialDealings, marshaled []byte, dealer int) (dkg.VerifiedDecryptionKeySharesForInnerDealings, error) {
	unverifiedShares, err := codec.Unmarshal(marshaled, dkg.NewUnverifiedDecryptionKeySharesForInnerDealings())
	if err != nil {
		return nil, err
	}

	verifiedDecryptionKeyShares, err := dkgInstance.VerifyDecryptionKeyShares(initialDealings, unverifiedShares, dealer)
	if err != nil {
		return nil, fmt.Errorf("failed to verify decryption key shares from dealer %d: %w", dealer, err)
	}

	return verifiedDecryptionKeyShares, nil
}

// Creates a new result package based on the committed inner dealings and serializes it as bytes to be included in the report.
func newResultPackage(dkgInstance dkg.DKG, innerDealings innerDealings, pluginConfig *dkgocrtypes.ReportingPluginConfig) ([]byte, error) {
	// Create the DKG result package based on the committed inner dealings
	result, err := dkgInstance.NewResult(innerDealings)
	if err != nil {
		return nil, fmt.Errorf("failed to create DKG result: %w", err)
	}
	resultPackage := ResultPackage{result, pluginConfig}

	// Serialize the result package
	marshaled, err := resultPackage.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DKG result package: %w", err)
	}

	return marshaled, nil
}

// Retrieves the DKG instance from cache if exists, otherwise creates a new one and updates the limits in cache.
func (p *DKGPlugin) getDKG(ctx context.Context) (dkg.DKG, error) {
	dkgInstance := p.cache.getDKG()

	if dkgInstance == nil {
		var err error
		dkgInstance, err = p.cache.newDKGAndUpdateLimits(ctx, p.db, p.iid, p.curve, p.dealers, p.recipients, p.f_D, p.t_R, p.keyring, p.pluginConfig.PreviousInstanceID)
		if err != nil {
			return nil, err
		}
	}

	return dkgInstance, nil
}
