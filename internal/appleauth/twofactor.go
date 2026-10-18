package appleauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	TwoFactorMethodTrustedDevice = "trusted-device"
	TwoFactorMethodPhone         = "phone"
)

// TwoFactorDeliverySMS asks Apple to text the verification code to a trusted
// phone number even when trusted devices could receive it.
const TwoFactorDeliverySMS = "sms"

var ErrNoTrustedPhoneNumbers = errors.New("no trusted phone numbers available")

// TwoFactorPreference is the caller's requested verification delivery. The
// zero value keeps Apple's default: trusted devices first, phone fallback after.
type TwoFactorPreference struct {
	Delivery string
	// PhoneID selects a trusted phone number; zero means the only one.
	PhoneID int
}

// TrustedPhoneSelectionError reports that the requested trusted phone number
// could not be resolved. RequestedID is zero when several numbers matched.
type TrustedPhoneSelectionError struct {
	RequestedID int
	Phones      []TrustedPhoneNumber
}

func (e *TrustedPhoneSelectionError) Error() string {
	options := make([]string, 0, len(e.Phones))
	for _, phone := range e.Phones {
		option := fmt.Sprintf("%d", phone.ID)
		if destination := strings.TrimSpace(phone.NumberWithDialCode); destination != "" {
			option += " (" + destination + ")"
		}
		options = append(options, option)
	}
	if e.RequestedID == 0 {
		return "multiple trusted phone numbers are available; select one by ID: " + strings.Join(options, ", ")
	}
	return fmt.Sprintf("trusted phone number ID %d is not available; select one by ID: %s", e.RequestedID, strings.Join(options, ", "))
}

type AmbiguousTrustedPhoneNumberError struct {
	Available []TrustedPhoneNumber
}

func (e *AmbiguousTrustedPhoneNumberError) Error() string {
	return (&TrustedPhoneSelectionError{Phones: e.Available}).Error()
}

func (e *AmbiguousTrustedPhoneNumberError) Unwrap() error {
	if e == nil {
		return nil
	}
	return &TrustedPhoneSelectionError{Phones: e.Available}
}

type TrustedPhoneNumberNotFoundError struct {
	ID        int
	Available []TrustedPhoneNumber
}

func (e *TrustedPhoneNumberNotFoundError) Error() string {
	return (&TrustedPhoneSelectionError{RequestedID: e.ID, Phones: e.Available}).Error()
}

func (e *TrustedPhoneNumberNotFoundError) Unwrap() error {
	if e == nil {
		return nil
	}
	return &TrustedPhoneSelectionError{RequestedID: e.ID, Phones: e.Available}
}

func FormatAvailablePhoneNumbers(phones []TrustedPhoneNumber) string {
	parts := make([]string, 0, len(phones))
	for _, p := range phones {
		dest := strings.TrimSpace(p.NumberWithDialCode)
		if dest != "" {
			parts = append(parts, fmt.Sprintf("%d (%s)", p.ID, dest))
		} else {
			parts = append(parts, strconv.Itoa(p.ID))
		}
	}
	return strings.Join(parts, ", ")
}

type TwoFactorPhoneSelector interface {
	SelectTwoFactorPhone(ctx context.Context, phones []TrustedPhoneNumber) (*TrustedPhoneNumber, error)
}

type UnsupportedTwoFactorMethodError struct {
	Method string
}

func (e *UnsupportedTwoFactorMethodError) Error() string {
	return fmt.Sprintf("unsupported verification method %q", e.Method)
}

type PhoneCodeRequestedError struct {
	Destination string
	Err         error
}

func (e *PhoneCodeRequestedError) Error() string {
	destination := strings.TrimSpace(e.Destination)
	if destination != "" {
		return fmt.Sprintf("trusted-device verification failed; verification code sent to %s", destination)
	}
	return "trusted-device verification failed; verification code sent to trusted phone number"
}

func (e *PhoneCodeRequestedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type MarshalPayloadError struct {
	Err error
}

func (e *MarshalPayloadError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *MarshalPayloadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type TwoFactorChallenge struct {
	Method                 string
	Destination            string
	Requested              bool
	PhoneFallbackAvailable bool
}

// IsPhoneMethod reports whether the challenge uses Apple phone-code delivery.
func (c *TwoFactorChallenge) IsPhoneMethod() bool {
	return c != nil && c.Method == TwoFactorMethodPhone
}

type TrustedPhoneNumber struct {
	ID                 int    `json:"id"`
	PushMode           string `json:"pushMode"`
	NumberWithDialCode string `json:"numberWithDialCode"`
}

type AuthOptions struct {
	NoTrustedDevices    bool
	TrustedPhoneNumbers []TrustedPhoneNumber
}

type AuthOptionsResponse struct {
	NoTrustedDevices    bool                 `json:"noTrustedDevices"`
	TrustedDevices      []map[string]any     `json:"trustedDevices"`
	TrustedPhoneNumbers []TrustedPhoneNumber `json:"trustedPhoneNumbers"`
	SecurityCode        struct {
		Length int `json:"length"`
	} `json:"securityCode"`
}

func (opts *AuthOptionsResponse) AuthOptions() *AuthOptions {
	if opts == nil {
		return &AuthOptions{}
	}
	shared := &AuthOptions{
		NoTrustedDevices: opts.NoTrustedDevices,
	}
	if len(opts.TrustedPhoneNumbers) == 0 {
		return shared
	}
	shared.TrustedPhoneNumbers = append([]TrustedPhoneNumber(nil), opts.TrustedPhoneNumbers...)
	return shared
}

type SessionState interface {
	TwoFactorMethod() string
	TwoFactorPhoneID() int
	TwoFactorPhoneMode() string
	TwoFactorDestination() string
	TwoFactorCodeRequested() bool
	TwoFactorPreference() TwoFactorPreference
	SetPreparedTwoFactorState(method string, phoneID int, phoneMode, destination string, requested bool)
	SetTwoFactorCodeRequested(requested bool)
}

type RequestLogger func(stage string, req *http.Request, resp *http.Response, body []byte, err error)

func ExtractServiceErrorCodes(respBody []byte) []string {
	var payload struct {
		ServiceErrors []struct {
			Code string `json:"code"`
		} `json:"serviceErrors"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil
	}
	if len(payload.ServiceErrors) == 0 {
		return nil
	}
	codes := make([]string, 0, len(payload.ServiceErrors))
	for _, serviceErr := range payload.ServiceErrors {
		code := strings.TrimSpace(serviceErr.Code)
		if code != "" {
			codes = append(codes, code)
		}
	}
	return codes
}

func IsAppleAccountActionRequiredSigninComplete(status int, respBody []byte) bool {
	if status != http.StatusPreconditionFailed {
		return false
	}
	var payload struct {
		AuthType string `json:"authType"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return false
	}
	switch strings.TrimSpace(payload.AuthType) {
	case "sa", "hsa", "non-sa", "hsa2":
		return true
	default:
		return false
	}
}

type TwoFactorSelectionState interface {
	SessionState
	RequestedTwoFactorMethod() string
	RequestedTwoFactorPhoneID() int
}

type TwoFactorOptions struct {
	Method      string
	PhoneID     int
	SelectPhone func(context.Context, []TrustedPhoneNumber) (*TrustedPhoneNumber, error)
}

func PrepareTwoFactorChallenge(ctx context.Context, session SessionState, getAuthOptions func(context.Context) (*AuthOptions, error)) (*TwoFactorChallenge, error) {
	var opts TwoFactorOptions
	if s, ok := session.(TwoFactorSelectionState); ok {
		opts.Method = s.RequestedTwoFactorMethod()
		opts.PhoneID = s.RequestedTwoFactorPhoneID()
	}
	return PrepareTwoFactorChallengeWithOptions(ctx, session, getAuthOptions, opts)
}

func PrepareTwoFactorChallengeWithOptions(ctx context.Context, session SessionState, getAuthOptions func(context.Context) (*AuthOptions, error), opts TwoFactorOptions) (*TwoFactorChallenge, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if method := session.TwoFactorMethod(); method != "" {
		return &TwoFactorChallenge{
			Method:                 method,
			Destination:            session.TwoFactorDestination(),
			Requested:              session.TwoFactorCodeRequested(),
			PhoneFallbackAvailable: method == TwoFactorMethodTrustedDevice && session.TwoFactorPhoneID() != 0,
		}, nil
	}

	pref := session.TwoFactorPreference()
	requestedMethod := strings.ToLower(strings.TrimSpace(opts.Method))
	if requestedMethod == "" {
		requestedMethod = strings.ToLower(strings.TrimSpace(pref.Delivery))
	}
	switch requestedMethod {
	case "", "sms", TwoFactorMethodPhone, TwoFactorMethodTrustedDevice:
	default:
		return nil, &UnsupportedTwoFactorMethodError{Method: opts.Method}
	}

	phoneID := opts.PhoneID
	if phoneID == 0 {
		phoneID = pref.PhoneID
	}

	authOpts, err := getAuthOptions(ctx)
	if err != nil {
		return nil, err
	}

	if authOpts.NoTrustedDevices && requestedMethod == TwoFactorMethodTrustedDevice {
		return nil, fmt.Errorf("trusted-device verification requested, but account has no trusted devices")
	}

	if requestedMethod == "sms" || requestedMethod == TwoFactorMethodPhone {
		if len(authOpts.TrustedPhoneNumbers) == 0 {
			return nil, fmt.Errorf("sms verification is unavailable: %w", ErrNoTrustedPhoneNumbers)
		}

		selected, err := selectSMSPhoneWithSelector(ctx, session, authOpts.TrustedPhoneNumbers, phoneID, opts.SelectPhone)
		if err != nil {
			return nil, err
		}

		phoneMode := strings.TrimSpace(selected.PushMode)
		if phoneMode == "" || requestedMethod == "sms" {
			phoneMode = "sms"
		}
		destination := strings.TrimSpace(selected.NumberWithDialCode)

		session.SetPreparedTwoFactorState(TwoFactorMethodPhone, selected.ID, phoneMode, destination, false)
		return &TwoFactorChallenge{
			Method:                 TwoFactorMethodPhone,
			Destination:            destination,
			Requested:              false,
			PhoneFallbackAvailable: false,
		}, nil
	}

	fallbackPhoneID := 0
	phoneMode := ""
	destination := ""
	if len(authOpts.TrustedPhoneNumbers) > 0 {
		var fallbackPhone *TrustedPhoneNumber
		if phoneID != 0 {
			for i := range authOpts.TrustedPhoneNumbers {
				if authOpts.TrustedPhoneNumbers[i].ID == phoneID {
					fallbackPhone = &authOpts.TrustedPhoneNumbers[i]
					break
				}
			}
		}
		if fallbackPhone == nil {
			fallbackPhone = &authOpts.TrustedPhoneNumbers[0]
		}
		phoneMode = strings.TrimSpace(fallbackPhone.PushMode)
		if phoneMode == "" {
			phoneMode = "sms"
		}
		fallbackPhoneID = fallbackPhone.ID
		destination = strings.TrimSpace(fallbackPhone.NumberWithDialCode)
	}

	if authOpts.NoTrustedDevices {
		if fallbackPhoneID == 0 {
			return nil, ErrNoTrustedPhoneNumbers
		}
		session.SetPreparedTwoFactorState(TwoFactorMethodPhone, fallbackPhoneID, phoneMode, destination, false)
		return &TwoFactorChallenge{
			Method:                 TwoFactorMethodPhone,
			Destination:            destination,
			Requested:              false,
			PhoneFallbackAvailable: false,
		}, nil
	}

	session.SetPreparedTwoFactorState(TwoFactorMethodTrustedDevice, fallbackPhoneID, phoneMode, destination, false)
	return &TwoFactorChallenge{
		Method:                 TwoFactorMethodTrustedDevice,
		Destination:            destination,
		Requested:              false,
		PhoneFallbackAvailable: fallbackPhoneID != 0,
	}, nil
}

func selectSMSPhoneWithSelector(ctx context.Context, session SessionState, phones []TrustedPhoneNumber, phoneID int, selectFn func(context.Context, []TrustedPhoneNumber) (*TrustedPhoneNumber, error)) (TrustedPhoneNumber, error) {
	if len(phones) == 0 {
		return TrustedPhoneNumber{}, fmt.Errorf("sms verification is unavailable: %w", ErrNoTrustedPhoneNumbers)
	}
	if phoneID != 0 {
		for _, phone := range phones {
			if phone.ID == phoneID {
				return phone, nil
			}
		}
		return TrustedPhoneNumber{}, &TrustedPhoneSelectionError{RequestedID: phoneID, Phones: phones}
	}
	if len(phones) == 1 {
		return phones[0], nil
	}
	if selectFn == nil {
		if s, ok := session.(TwoFactorPhoneSelector); ok {
			selectFn = s.SelectTwoFactorPhone
		}
	}
	if selectFn != nil {
		chosen, err := selectFn(ctx, phones)
		if err != nil {
			return TrustedPhoneNumber{}, err
		}
		if chosen != nil {
			return *chosen, nil
		}
	}
	return TrustedPhoneNumber{}, &TrustedPhoneSelectionError{Phones: phones}
}

func EnsureTwoFactorCodeRequested(ctx context.Context, session SessionState, getAuthOptions func(context.Context) (*AuthOptions, error), requestPhoneCode func(context.Context, int, string) error) (*TwoFactorChallenge, error) {
	challenge, err := PrepareTwoFactorChallenge(ctx, session, getAuthOptions)
	if err != nil {
		return nil, err
	}
	if challenge.Method != TwoFactorMethodPhone {
		return challenge, nil
	}
	if session.TwoFactorCodeRequested() {
		challenge.Requested = true
		return challenge, nil
	}
	phoneID := session.TwoFactorPhoneID()
	if phoneID == 0 {
		return nil, ErrNoTrustedPhoneNumbers
	}
	if err := requestPhoneCode(ctx, phoneID, session.TwoFactorPhoneMode()); err != nil {
		return nil, err
	}
	session.SetTwoFactorCodeRequested(true)
	challenge.Requested = true
	return challenge, nil
}

func SubmitTwoFactorCode(ctx context.Context, session SessionState, code string, getAuthOptions func(context.Context) (*AuthOptions, error), requestPhoneCode func(context.Context, int, string) error, submitTrustedDeviceCode func(context.Context, string) error, submitPhoneCode func(context.Context, string, int, string) error, finalize func(context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	challenge, err := PrepareTwoFactorChallenge(ctx, session, getAuthOptions)
	if err != nil {
		return err
	}

	switch challenge.Method {
	case TwoFactorMethodPhone:
		phoneID := session.TwoFactorPhoneID()
		phoneMode := session.TwoFactorPhoneMode()
		destination := session.TwoFactorDestination()
		if phoneID == 0 {
			return ErrNoTrustedPhoneNumbers
		}
		if !session.TwoFactorCodeRequested() {
			if requestPhoneCode == nil {
				return ErrNoTrustedPhoneNumbers
			}
			if err := requestPhoneCode(ctx, phoneID, phoneMode); err != nil {
				return err
			}
			session.SetPreparedTwoFactorState(TwoFactorMethodPhone, phoneID, phoneMode, destination, true)
		}
		if err := submitPhoneCode(ctx, code, phoneID, phoneMode); err != nil {
			return err
		}
		session.SetPreparedTwoFactorState(TwoFactorMethodPhone, phoneID, phoneMode, destination, true)
		return finalize(ctx)
	case TwoFactorMethodTrustedDevice:
		if err := submitTrustedDeviceCode(ctx, code); err != nil {
			phoneID := session.TwoFactorPhoneID()
			if phoneID == 0 {
				return err
			}
			phoneMode := session.TwoFactorPhoneMode()
			destination := session.TwoFactorDestination()
			if !session.TwoFactorCodeRequested() {
				if requestPhoneCode == nil {
					return err
				}
				if requestErr := requestPhoneCode(ctx, phoneID, phoneMode); requestErr != nil {
					return requestErr
				}
			}
			session.SetPreparedTwoFactorState(TwoFactorMethodPhone, phoneID, phoneMode, destination, true)
			return &PhoneCodeRequestedError{Destination: destination, Err: err}
		}
		return finalize(ctx)
	default:
		return &UnsupportedTwoFactorMethodError{Method: challenge.Method}
	}
}

func DoTwoFactorJSONRequest(ctx context.Context, client *http.Client, headers http.Header, stage, method, requestURL string, payload any, marshalPayload func(any) ([]byte, error), setModifiedCookieHeader func(*http.Request), log RequestLogger) (int, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := marshalPayload(payload)
	if err != nil {
		return 0, nil, &MarshalPayloadError{Err: err}
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if setModifiedCookieHeader != nil {
		setModifiedCookieHeader(req)
	}

	resp, err := client.Do(req)
	if err != nil {
		if log != nil {
			log(stage, req, nil, nil, err)
		}
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if log != nil {
		log(stage, req, resp, respBody, nil)
	}
	return resp.StatusCode, respBody, nil
}
