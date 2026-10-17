package web

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleauth"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

// stubTwoFactorDeliveryLogin stubs a sign-in that reaches 2FA and records the
// delivery preference visible when the challenge is prepared.
func stubTwoFactorDeliveryLogin(t *testing.T) (*appleauth.TwoFactorPreference, *bool) {
	t.Helper()
	origLogin := webLoginFn
	origPrepare := prepareTwoFactorChallengeFn
	origEnsure := ensureTwoFactorCodeRequestedFn
	origSubmit := submitTwoFactorCodeFn
	origStatusWriter := twoFactorStatusWriter
	t.Cleanup(func() {
		webLoginFn = origLogin
		prepareTwoFactorChallengeFn = origPrepare
		ensureTwoFactorCodeRequestedFn = origEnsure
		submitTwoFactorCodeFn = origSubmit
		twoFactorStatusWriter = origStatusWriter
	})

	var (
		seen     appleauth.TwoFactorPreference
		loggedIn bool
	)
	webLoginFn = func(ctx context.Context, creds webcore.LoginCredentials) (*webcore.AuthSession, error) {
		loggedIn = true
		return &webcore.AuthSession{}, &webcore.TwoFactorRequiredError{}
	}
	prepareTwoFactorChallengeFn = func(ctx context.Context, session *webcore.AuthSession) (*webcore.TwoFactorChallenge, error) {
		seen = session.TwoFactorPreference()
		return &webcore.TwoFactorChallenge{Method: "phone", Destination: "+1 (•••) •••-••22"}, nil
	}
	ensureTwoFactorCodeRequestedFn = func(ctx context.Context, session *webcore.AuthSession) (*webcore.TwoFactorChallenge, error) {
		return &webcore.TwoFactorChallenge{Method: "phone", Destination: "+1 (•••) •••-••22", Requested: true}, nil
	}
	submitTwoFactorCodeFn = func(ctx context.Context, session *webcore.AuthSession, code string) error {
		return nil
	}
	twoFactorStatusWriter = io.Discard
	return &seen, &loggedIn
}

func readStubTwoFactorCode(context.Context, string) (string, error) {
	return "123456", nil
}

func TestLoginWithOptionalTwoFactorAppliesPreferenceLayeredOverTimeout(t *testing.T) {
	t.Setenv(webTwoFactorMethodEnv, "")
	t.Setenv(webTwoFactorPhoneIDEnv, "")
	seen, _ := stubTwoFactorDeliveryLogin(t)

	// The sign-in flow strips request timeouts, which also drops values that
	// were layered above them; the preference must survive that.
	timedCtx, cancel := shared.ContextWithTimeout(context.Background())
	defer cancel()
	want := appleauth.TwoFactorPreference{Delivery: appleauth.TwoFactorDeliverySMS, PhoneID: 2}
	ctx := contextWithTwoFactorPreference(timedCtx, want)

	if _, err := loginWithOptionalTwoFactor(ctx, "user@example.com", "secret", "", nil, readStubTwoFactorCode, "read-code"); err != nil {
		t.Fatalf("loginWithOptionalTwoFactor returned error: %v", err)
	}
	if *seen != want {
		t.Fatalf("challenge saw preference %+v, want %+v", *seen, want)
	}
}

func TestLoginWithOptionalTwoFactorFallsBackToEnvironmentPreference(t *testing.T) {
	t.Setenv(webTwoFactorMethodEnv, "SMS")
	t.Setenv(webTwoFactorPhoneIDEnv, "7")
	seen, _ := stubTwoFactorDeliveryLogin(t)

	if _, err := loginWithOptionalTwoFactor(context.Background(), "user@example.com", "secret", "", nil, readStubTwoFactorCode, "read-code"); err != nil {
		t.Fatalf("loginWithOptionalTwoFactor returned error: %v", err)
	}
	want := appleauth.TwoFactorPreference{Delivery: appleauth.TwoFactorDeliverySMS, PhoneID: 7}
	if *seen != want {
		t.Fatalf("challenge saw preference %+v, want %+v", *seen, want)
	}
}

func TestLoginWithOptionalTwoFactorRejectsInvalidEnvironmentBeforeSignIn(t *testing.T) {
	t.Setenv(webTwoFactorMethodEnv, "push")
	t.Setenv(webTwoFactorPhoneIDEnv, "")
	_, loggedIn := stubTwoFactorDeliveryLogin(t)

	_, err := loginWithOptionalTwoFactor(context.Background(), "user@example.com", "secret", "", nil, readStubTwoFactorCode, "read-code")
	if err == nil || !strings.Contains(err.Error(), webTwoFactorMethodEnv+" must be one of: auto, sms") {
		t.Fatalf("expected invalid environment error, got %v", err)
	}
	if *loggedIn {
		t.Fatal("expected validation to fail before sending credentials")
	}
}

func TestResolveTwoFactorPreference(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		phoneID int
		env     map[string]string
		want    appleauth.TwoFactorPreference
	}{
		{name: "default"},
		{name: "explicit auto", method: "auto"},
		{name: "sms flag", method: "sms", want: appleauth.TwoFactorPreference{Delivery: "sms"}},
		{name: "sms flag with phone", method: " SMS ", phoneID: 3, want: appleauth.TwoFactorPreference{Delivery: "sms", PhoneID: 3}},
		{name: "sms env", env: map[string]string{webTwoFactorMethodEnv: "sms", webTwoFactorPhoneIDEnv: "4"}, want: appleauth.TwoFactorPreference{Delivery: "sms", PhoneID: 4}},
		{name: "flag phone overrides env phone", method: "sms", phoneID: 5, env: map[string]string{webTwoFactorPhoneIDEnv: "4"}, want: appleauth.TwoFactorPreference{Delivery: "sms", PhoneID: 5}},
		{name: "auto flag overrides env sms", method: "auto", env: map[string]string{webTwoFactorMethodEnv: "sms"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(webTwoFactorMethodEnv, "")
			t.Setenv(webTwoFactorPhoneIDEnv, "")
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			got, err := resolveTwoFactorPreference(tt.method, tt.phoneID)
			if err != nil {
				t.Fatalf("resolveTwoFactorPreference() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("resolveTwoFactorPreference() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
