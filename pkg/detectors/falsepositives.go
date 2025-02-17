package detectors

import (
	_ "embed"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var DefaultFalsePositives = []FalsePositive{"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****"}

type FalsePositive string

type CustomFalsePositiveChecker interface {
	// IsFalsePositive returns two values:
	// 1. Whether the result is a false positive.
	// 2. If #1 is `true`, the reason why.
	IsFalsePositive(result Result) (bool, string)
}

//go:embed "badlist.txt"
var badList []byte

//go:embed "words.txt"
var wordList []byte

//go:embed "programmingbooks.txt"
var programmingBookWords []byte

var filter *ahocorasick.Trie

func init() {
	builder := ahocorasick.NewTrieBuilder()

	wordList := bytesToCleanWordList(wordList)
	builder.AddStrings(wordList)

	badList := bytesToCleanWordList(badList)
	builder.AddStrings(badList)

	programmingBookWords := bytesToCleanWordList(programmingBookWords)
	builder.AddStrings(programmingBookWords)

	filter = builder.Build()
}

func GetFalsePositiveCheck(detector Detector) func(Result) (bool, string) {
	checker, ok := detector.(CustomFalsePositiveChecker)
	if ok {
		return checker.IsFalsePositive
	}

	return func(res Result) (bool, string) {
		return IsKnownFalsePositive(string(res.Raw), DefaultFalsePositives, true)
	}
}

// IsKnownFalsePositive returns whether a finding is (likely) a known false positive, and the reason for the detection.
//
// Currently, this includes: english word in key or matches common example patterns.
// Only the secret key material should be passed into this function
func IsKnownFalsePositive(match string, falsePositives []FalsePositive, wordCheck bool) (bool, string) {
	if !utf8.ValidString(match) {
		return true, "invalid utf8"
	}
	lower := strings.ToLower(match)
	for _, fp := range falsePositives {
		fps := string(fp)
		if strings.Contains(lower, fps) {
			return true, "matches term: " + fps
		}
	}

	if wordCheck {
		if m := filter.MatchFirstString(lower); m != nil {
			return true, "matches wordlist: " + m.MatchString()
		}
	}

	return false, ""
}

func HasDigit(key string) bool {
	for _, ch := range key {
		if unicode.IsDigit(ch) {
			return true
		}
	}

	return false
}

func bytesToCleanWordList(data []byte) []string {
	words := make(map[string]struct{})
	for _, word := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(word) != "" {
			words[strings.TrimSpace(strings.ToLower(word))] = struct{}{}
		}
	}

	wordList := make([]string, 0, len(words))
	for word := range words {
		wordList = append(wordList, word)
	}
	return wordList
}

func StringShannonEntropy(input string) float64 {
	chars := make(map[rune]float64)
	inverseTotal := 1 / float64(len(input)) // precompute the inverse

	for _, char := range input {
		chars[char]++
	}

	entropy := 0.0
	for _, count := range chars {
		probability := count * inverseTotal
		entropy += probability * math.Log2(probability)
	}

	return -entropy
}

// FilterResultsWithEntropy filters out determinately unverified results that have a shannon entropy below the given value.
func FilterResultsWithEntropy(ctx context.Context, results []Result, entropy float64, shouldLog bool) []Result {
	var filteredResults []Result
	for _, result := range results {
		if !result.Verified {
			if result.Raw != nil {
				if StringShannonEntropy(string(result.Raw)) >= entropy {
					filteredResults = append(filteredResults, result)
				} else {
					if shouldLog {
						ctx.Logger().Info("Filtered out result with low entropy", "result", result)
					}
				}
			} else {
				filteredResults = append(filteredResults, result)
			}
		} else {
			filteredResults = append(filteredResults, result)
		}
	}
	return filteredResults
}

// FilterKnownFalsePositives filters out known false positives from the results.
func FilterKnownFalsePositives(ctx context.Context, detector Detector, results []Result, shouldLog bool) []Result {
	var filteredResults []Result

	isFalsePositive := GetFalsePositiveCheck(detector)

	for _, result := range results {
		if !result.Verified && result.Raw != nil {
			isFp, reason := isFalsePositive(result)
			if !isFp {
				filteredResults = append(filteredResults, result)
			} else if shouldLog {
				ctx.Logger().Info("Filtered out known false positive", "result", result, "reason", reason)
			}
		} else {
			filteredResults = append(filteredResults, result)
		}
	}
	return filteredResults
}
