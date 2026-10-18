package web

import (
	"context"
	"errors"
	"fmt"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleauth"
)

var (
	_ appleauth.SessionState            = (*AuthSession)(nil)
	_ appleauth.TwoFactorSelectionState = (*AuthSession)(nil)
	_ appleauth.TwoFactorPhoneSelector  = (*AuthSession)(nil)
)

func (s *AuthSession) TwoFactorMethod() string {
	if s == nil {
		return ""
	}
	return s.twoFactorMethod
}

func (s *AuthSession) TwoFactorPhoneID() int {
	if s == nil {
		return 0
	}
	return s.twoFactorPhoneID
}

func (s *AuthSession) TwoFactorPhoneMode() string {
	if s == nil {
		return ""
	}
	return s.twoFactorPhoneMode
}

func (s *AuthSession) TwoFactorDestination() string {
	if s == nil {
		return ""
	}
	return s.twoFactorDestination
}

func (s *AuthSession) TwoFactorCodeRequested() bool {
	return s != nil && s.twoFactorCodeRequested
}

func (s *AuthSession) TwoFactorPreference() appleauth.TwoFactorPreference {
	if s == nil {
		return appleauth.TwoFactorPreference{}
	}
	return s.twoFactorPreference
}

// SetTwoFactorPreference records the requested verification delivery for the
// next challenge preparation.
func (s *AuthSession) SetTwoFactorPreference(preference appleauth.TwoFactorPreference) {
	if s == nil {
		return
	}
	s.twoFactorPreference = preference
}

func (s *AuthSession) RequestedTwoFactorMethod() string {
	if s == nil {
		return ""
	}
	return s.twoFactorPreference.Delivery
}

func (s *AuthSession) RequestedTwoFactorPhoneID() int {
	if s == nil {
		return 0
	}
	return s.twoFactorPreference.PhoneID
}

func (s *AuthSession) SetRequestedTwoFactor(method string, phoneID int) {
	if s == nil {
		return
	}
	s.twoFactorPreference = appleauth.TwoFactorPreference{Delivery: method, PhoneID: phoneID}
}

func (s *AuthSession) SetSelectPhone(fn func(context.Context, []appleauth.TrustedPhoneNumber) (*appleauth.TrustedPhoneNumber, error)) {
	if s == nil {
		return
	}
	s.selectPhoneFn = fn
}

func (s *AuthSession) SelectTwoFactorPhone(ctx context.Context, phones []appleauth.TrustedPhoneNumber) (*appleauth.TrustedPhoneNumber, error) {
	if s == nil || s.selectPhoneFn == nil {
		return nil, nil
	}
	return s.selectPhoneFn(ctx, phones)
}

func (s *AuthSession) SetPreparedTwoFactorState(method string, phoneID int, phoneMode, destination string, requested bool) {
	if s == nil {
		return
	}
	s.twoFactorMethod = method
	s.twoFactorPhoneID = phoneID
	s.twoFactorPhoneMode = phoneMode
	s.twoFactorDestination = destination
	s.twoFactorCodeRequested = requested
}

func (s *AuthSession) SetTwoFactorCodeRequested(requested bool) {
	if s == nil {
		return
	}
	s.twoFactorCodeRequested = requested
}

func wrapWebTwoFactorFlowError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, appleauth.ErrNoTrustedPhoneNumbers) {
		return fmt.Errorf("2fa failed: %w", err)
	}
	var unsupported *appleauth.UnsupportedTwoFactorMethodError
	var phoneSelection *appleauth.TrustedPhoneSelectionError
	if errors.As(err, &unsupported) || errors.As(err, &phoneSelection) {
		return fmt.Errorf("2fa failed: %w", err)
	}
	var ambiguous *appleauth.AmbiguousTrustedPhoneNumberError
	if errors.As(err, &ambiguous) {
		return fmt.Errorf("2fa failed: %w", err)
	}
	var notFound *appleauth.TrustedPhoneNumberNotFoundError
	if errors.As(err, &notFound) {
		return fmt.Errorf("2fa failed: %w", err)
	}
	return err
}
