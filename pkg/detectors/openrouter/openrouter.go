package openrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b(sk-or-v1-[0-9a-fA-F]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sk-or-v1-"}
}

// FromData will find and optionally verify OpenAI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OpenRouter,
			Redacted:     token[:9] + "..." + token[69:],
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, extraData, verificationErr := verifyToken(ctx, client, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://openrouter.ai/api/v1/key", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var keyResponse keyResponse
		if err = json.NewDecoder(res.Body).Decode(&keyResponse); err != nil {
			return false, nil, err
		}

		key := keyResponse.Data
		extraData := map[string]string{
			"label":           key.Label,
			"limit":           fmt.Sprintf("%d", key.Limit),
			"usage":           fmt.Sprintf("%d", key.Usage),
			"is_free_tier":    strconv.FormatBool(key.IsFreeTier),
			"limit_remaining": fmt.Sprintf("%d", key.LimitRemaining),
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		// Invalid
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// TODO: Add secret context?? Information about access, ownership etc
type keyResponse struct {
	Data key `json:"data"`
}

type key struct {
	Label          string `json:"label"`
	Limit          int32  `json:"limit"`
	Usage          int32  `json:"usage"`
	IsFreeTier     bool   `json:"is_free_tier"`
	LimitRemaining int32  `json:"limit_remaining"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenRouter
}
