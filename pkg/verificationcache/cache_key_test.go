package verificationcache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// cacheKeyDetector is a testDetector that also contributes a detector-specific
// cache key component, standing in for a custom detector whose DetectorType is
// shared with other detectors.
type cacheKeyDetector struct {
	testDetector
	cacheKey []byte
}

func (d *cacheKeyDetector) CacheKey() ([]byte, error) { return d.cacheKey, nil }

var _ detectors.CacheKeyer = (*cacheKeyDetector)(nil)

func resultWithSecret(secret string) detectors.Result {
	return detectors.Result{
		DetectorType: detector_typepb.DetectorType_CustomRegex,
		Raw:          []byte(secret),
	}
}

// TestGetResultCacheKey_DetectorIsolation proves two detectors that return the
// same DetectorType and see the same secret get distinct cache keys when their
// CacheKey components differ, and that the same detector keeps a stable key.
func TestGetResultCacheKey_DetectorIsolation(t *testing.T) {
	t.Parallel()

	cache := New(simple.NewCache[detectors.Result](), &InMemoryMetrics{})
	result := resultWithSecret("same-token")

	detectorA := &cacheKeyDetector{cacheKey: []byte("detector-a")}
	detectorB := &cacheKeyDetector{cacheKey: []byte("detector-b")}

	keyA1 := getResultCacheKey(t, cache, detectorA, result)
	keyA2 := getResultCacheKey(t, cache, detectorA, result)
	keyB := getResultCacheKey(t, cache, detectorB, result)

	assert.Equal(t, keyA1, keyA2, "the same detector must produce a stable key")
	assert.NotEqual(t, keyA1, keyB, "distinct detectors must not share a cache key")
}

// TestGetResultCacheKey_ConfigurationChange forces a miss whenever the
// detector's CacheKey component changes, even if the secret is identical.
func TestGetResultCacheKey_ConfigurationChange(t *testing.T) {
	t.Parallel()

	cache := New(simple.NewCache[detectors.Result](), &InMemoryMetrics{})
	result := resultWithSecret("same-token")

	before := &cacheKeyDetector{cacheKey: []byte("endpoint-1")}
	after := &cacheKeyDetector{cacheKey: []byte("endpoint-2")}

	assert.NotEqual(t,
		getResultCacheKey(t, cache, before, result),
		getResultCacheKey(t, cache, after, result),
		"a verification configuration change must invalidate the cache key")
}

// TestGetResultCacheKey_SecretStillPartOfKey proves the detector component is
// additive: different secrets under the same detector still key separately,
// and detectors without a CacheKey fall back to the legacy Raw/RawV2/type key.
func TestGetResultCacheKey_SecretAndLegacyFallback(t *testing.T) {
	t.Parallel()

	cache := New(simple.NewCache[detectors.Result](), &InMemoryMetrics{})
	detector := &cacheKeyDetector{cacheKey: []byte("detector-a")}

	assert.NotEqual(t,
		getResultCacheKey(t, cache, detector, resultWithSecret("token-one")),
		getResultCacheKey(t, cache, detector, resultWithSecret("token-two")),
		"distinct secrets must not share a cache key")

	// A plain detector (no CacheKeyer) must keep working and distinguish secrets.
	legacy := &testDetector{}
	legacyKey1 := getResultCacheKey(t, cache, legacy, resultWithSecret("token-one"))
	legacyKey2 := getResultCacheKey(t, cache, legacy, resultWithSecret("token-two"))
	assert.NotEqual(t, legacyKey1, legacyKey2)

	// Raw and RawV2 are length-prefixed, so two Raw/RawV2 splits that join to
	// identical bytes must not collide.
	split1 := detectors.Result{Raw: []byte("ab"), RawV2: []byte("c")}
	split2 := detectors.Result{Raw: []byte("a"), RawV2: []byte("bc")}
	assert.NotEqual(t,
		getResultCacheKey(t, cache, legacy, split1),
		getResultCacheKey(t, cache, legacy, split2),
		"length-prefixed key components must be unambiguous")
}

// TestFromData_CacheKeyerIsolation exercises the full FromData path: a cached
// verdict from one detector must never be replayed for a second detector with
// a different CacheKey, even when DetectorType and the secret match.
func TestFromData_CacheKeyerIsolation(t *testing.T) {
	t.Parallel()

	metrics := &InMemoryMetrics{}
	cache := New(simple.NewCache[detectors.Result](), metrics)

	verifiedResult := resultWithSecret("shared-token")
	verifiedResult.Verified = true

	unverifiedResult := resultWithSecret("shared-token")

	detectorA := &cacheKeyDetector{
		cacheKey:     []byte("detector-a"),
		testDetector: testDetector{results: []detectors.Result{verifiedResult}},
	}
	detectorB := &cacheKeyDetector{
		cacheKey:     []byte("detector-b"),
		testDetector: testDetector{results: []detectors.Result{unverifiedResult}},
	}

	first, err := cache.FromData(logContext.Background(), detectorA, true, false, nil)
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.True(t, first[0].Verified)

	second, err := cache.FromData(logContext.Background(), detectorB, true, false, nil)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.False(t, second[0].VerificationFromCache,
		"the second detector must not reuse the first detector's cached verdict")
	assert.False(t, second[0].Verified)

	// Repeating detector A serves its own entry from the cache.
	repeat, err := cache.FromData(logContext.Background(), detectorA, true, false, nil)
	require.NoError(t, err)
	require.Len(t, repeat, 1)
	assert.True(t, repeat[0].VerificationFromCache)
	assert.True(t, repeat[0].Verified)
	assert.Equal(t, int32(2), metrics.ResultCacheMisses.Load())
	assert.Equal(t, int32(1), metrics.ResultCacheHits.Load())
}
