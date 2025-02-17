//go:build detectors
// +build detectors

package detectors

import (
	"context"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type fakeDetector struct{}
type customFalsePositiveChecker struct{ fakeDetector }

func (d fakeDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	return nil, nil
}

func (d fakeDetector) Keywords() []string {
	return nil
}

func (d fakeDetector) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType(0)
}

func (d customFalsePositiveChecker) IsFalsePositive(result Result) (bool, string) {
	return IsKnownFalsePositive(string(result.Raw), []FalsePositive{"a specific magic string"}, false)
}

func TestFilterKnownFalsePositives_DefaultLogic(t *testing.T) {
	results := []Result{
		{Raw: []byte("00000")},           // "default" false positive list
		{Raw: []byte("number")},          // from wordlist
		{Raw: []byte("hga8adshla3434g")}, // real secret
	}
	expected := []Result{
		{Raw: []byte("hga8adshla3434g")},
	}
	filtered := FilterKnownFalsePositives(logContext.Background(), fakeDetector{}, results, false)
	assert.ElementsMatch(t, expected, filtered)
}

func TestFilterKnownFalsePositives_CustomLogic(t *testing.T) {
	results := []Result{
		{Raw: []byte("a specific magic string")}, // specific target
		{Raw: []byte("00000")},                   // "default" false positive list
		{Raw: []byte("number")},                  // from wordlist
		{Raw: []byte("hga8adshla3434g")},         // real secret
	}
	expected := []Result{
		{Raw: []byte("00000")},
		{Raw: []byte("number")},
		{Raw: []byte("hga8adshla3434g")},
	}
	filtered := FilterKnownFalsePositives(logContext.Background(), customFalsePositiveChecker{}, results, false)
	assert.ElementsMatch(t, expected, filtered)
}

func TestIsFalsePositive(t *testing.T) {
	type args struct {
		match          string
		falsePositives []FalsePositive
		useWordlist    bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "fp",
			args: args{
				match:          "example",
				falsePositives: DefaultFalsePositives,
				useWordlist:    false,
			},
			want: true,
		},
		{
			name: "fp - in wordlist",
			args: args{
				match:          "sdfdsfprivatesfsdfd",
				falsePositives: DefaultFalsePositives,
				useWordlist:    true,
			},
			want: true,
		},
		{
			name: "fp - not in wordlist",
			args: args{
				match:          "sdfdsfsfsdfd",
				falsePositives: DefaultFalsePositives,
				useWordlist:    true,
			},
			want: false,
		},
		{
			name: "not fp",
			args: args{
				match:          "notafp123",
				falsePositives: DefaultFalsePositives,
				useWordlist:    false,
			},
			want: false,
		},
		{
			name: "fp - in wordlist exact match",
			args: args{
				match:          "private",
				falsePositives: DefaultFalsePositives,
				useWordlist:    true,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := IsKnownFalsePositive(tt.args.match, tt.args.falsePositives, tt.args.useWordlist); got != tt.want {
				t.Errorf("IsKnownFalsePositive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringShannonEntropy(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want float64
	}{
		{
			name: "entropy 1",
			args: args{
				input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			want: 0,
		},
		{
			name: "entropy 2",
			args: args{
				input: "aaaaaaaaaaaaaaaaaaaaaaaaaaab",
			},
			want: 0.22228483068568816,
		},
		{
			name: "entropy 3",
			args: args{
				input: "aaaaaaaaaaaaaaaaaaaaaaaaaaabaaaaaaaaaaaaaaaaaaaaaaaaaaab",
			},
			want: 0.22228483068568816,
		},
		{
			name: "empty",
			args: args{
				input: "",
			},
			want: 0.0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StringShannonEntropy(tt.args.input); got != tt.want {
				t.Errorf("StringShannonEntropy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkDefaultIsKnownFalsePositive(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Use a string that won't be found in any dictionary for the worst case check.
		IsKnownFalsePositive("aoeuaoeuaoeuaoeuaoeuaoeu", DefaultFalsePositives, true)
	}
}
