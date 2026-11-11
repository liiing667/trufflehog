package custom_detectors

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache"
)

const cacheIsolationChunk = `token="abcdef123456"`

// countingWebhook is an offline webhook that replies with status and counts
// inbound requests, so tests can assert whether verification actually ran or
// was served from the verification cache.
func countingWebhook(t *testing.T, status int) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func cacheIsolationDetector(t *testing.T, name, endpoint string) *CustomRegexWebhook {
	t.Helper()
	detector, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     name,
		Keywords: []string{"token"},
		Regex:    map[string]string{"token": `token="([^"]+)"`},
		Verify: []*custom_detectorspb.VerifierConfig{{
			Endpoint:      endpoint,
			Unsafe:        true,
			SuccessRanges: []string{"200"},
		}},
	})
	require.NoError(t, err)
	return detector
}

// runVerifyData drives one verification pass through the cache over data.
func runVerifyData(
	t *testing.T,
	cache *verificationcache.VerificationCache,
	detector detectors.Detector,
	data []byte,
) []detectors.Result {
	t.Helper()
	results, err := cache.FromData(
		logContext.Background(),
		detector,
		true,
		false,
		data)
	require.NoError(t, err)
	return results
}

// runVerify drives one verification pass over the single-secret fixture chunk.
func runVerify(t *testing.T, cache *verificationcache.VerificationCache, detector detectors.Detector) detectors.Result {
	t.Helper()
	results := runVerifyData(t, cache, detector, []byte(cacheIsolationChunk))
	require.Len(t, results, 1)
	return results[0]
}

// TestVerificationCache_DistinctWebhooksIsolated sends the same token to two
// differently named custom detectors backed by different webhooks. The second
// detector must not inherit the first detector's cached verdict.
func TestVerificationCache_DistinctWebhooksIsolated(t *testing.T) {
	t.Parallel()

	okServer, okHits := countingWebhook(t, http.StatusOK)
	deniedServer, deniedHits := countingWebhook(t, http.StatusUnauthorized)

	cache := verificationcache.New(simple.NewCache[detectors.Result](), &verificationcache.InMemoryMetrics{})

	verified := runVerify(t, cache, cacheIsolationDetector(t, "detector-one", okServer.URL))
	assert.True(t, verified.Verified)

	denied := runVerify(t, cache, cacheIsolationDetector(t, "detector-two", deniedServer.URL))
	assert.False(t, denied.Verified, "the second webhook's verdict must not be reused from the first detector's cache")
	assert.False(t, denied.VerificationFromCache)

	assert.Equal(t, int64(1), atomic.LoadInt64(okHits))
	assert.Equal(t, int64(1), atomic.LoadInt64(deniedHits), "each webhook must be contacted independently")

	// Repeating the first detector hits its own cached entry.
	repeated := runVerify(t, cache, cacheIsolationDetector(t, "detector-one", okServer.URL))
	assert.True(t, repeated.VerificationFromCache)
	assert.True(t, repeated.Verified)
	assert.Equal(t, int64(1), atomic.LoadInt64(okHits), "a repeat must be served from the cache")
}

// TestVerificationCache_SameNameDifferentEndpointIsolated proves the endpoint
// (part of the verification configuration), not just the detector name,
// participates in the cache key.
func TestVerificationCache_SameNameDifferentEndpointIsolated(t *testing.T) {
	t.Parallel()

	okServer, okHits := countingWebhook(t, http.StatusOK)
	deniedServer, deniedHits := countingWebhook(t, http.StatusUnauthorized)

	cache := verificationcache.New(simple.NewCache[detectors.Result](), &verificationcache.InMemoryMetrics{})

	first := runVerify(t, cache, cacheIsolationDetector(t, "same-name", okServer.URL))
	assert.True(t, first.Verified)

	second := runVerify(t, cache, cacheIsolationDetector(t, "same-name", deniedServer.URL))
	assert.False(t, second.Verified, "a changed endpoint must miss the cache even with an identical detector name")
	assert.False(t, second.VerificationFromCache)

	assert.Equal(t, int64(1), atomic.LoadInt64(okHits))
	assert.Equal(t, int64(1), atomic.LoadInt64(deniedHits))
}

// TestVerificationCache_EndpointChangeMissesAndReHits verifies that an
// unchanged configuration keeps hitting, and that changing it forces a miss;
// switching back to the original configuration hits the original entry again.
func TestVerificationCache_EndpointChangeMissesAndReHits(t *testing.T) {
	t.Parallel()

	serverA, hitsA := countingWebhook(t, http.StatusOK)
	serverB, hitsB := countingWebhook(t, http.StatusOK)

	cache := verificationcache.New(simple.NewCache[detectors.Result](), &verificationcache.InMemoryMetrics{})

	runVerify(t, cache, cacheIsolationDetector(t, "movable", serverA.URL))
	runVerify(t, cache, cacheIsolationDetector(t, "movable", serverA.URL))
	assert.Equal(t, int64(1), atomic.LoadInt64(hitsA), "identical configuration must hit the cache")

	runVerify(t, cache, cacheIsolationDetector(t, "movable", serverB.URL))
	assert.Equal(t, int64(1), atomic.LoadInt64(hitsB), "the new endpoint must be contacted")

	runVerify(t, cache, cacheIsolationDetector(t, "movable", serverA.URL))
	assert.Equal(t, int64(1), atomic.LoadInt64(hitsA), "returning to the original endpoint must reuse its cached entry")
}

// TestVerificationCache_DuplicateSecretsHitCache runs the same detector over a
// chunk containing the same secret twice and confirms a repeated pass reuses
// both cached verdicts rather than contacting the webhook again.
func TestVerificationCache_DuplicateSecretsHitCache(t *testing.T) {
	t.Parallel()

	server, hits := countingWebhook(t, http.StatusOK)
	detector := cacheIsolationDetector(t, "dupes", server.URL)
	cache := verificationcache.New(simple.NewCache[detectors.Result](), &verificationcache.InMemoryMetrics{})

	const duplicateChunk = `token="abcdef123456" token="abcdef123456"`
	first := runVerifyData(t, cache, detector, []byte(duplicateChunk))
	require.Len(t, first, 2, "the duplicate fixture must produce two matches")
	assert.Equal(t, int64(2), atomic.LoadInt64(hits), "the first pass verifies both matches")
	for _, result := range first {
		assert.True(t, result.Verified)
	}

	second := runVerifyData(t, cache, detector, []byte(duplicateChunk))
	require.Len(t, second, 2)
	assert.Equal(t, int64(2), atomic.LoadInt64(hits), "the repeat must be served from the cache")
	for _, result := range second {
		assert.True(t, result.VerificationFromCache)
		assert.True(t, result.Verified)
	}
}

// TestVerificationCache_DoesNotStoreSecrets asserts cached entries have their
// raw secret material cleared while the verification verdict is retained.
func TestVerificationCache_DoesNotStoreSecrets(t *testing.T) {
	t.Parallel()

	server, _ := countingWebhook(t, http.StatusOK)
	detector := cacheIsolationDetector(t, "no-secrets", server.URL)

	resultCache := simple.NewCache[detectors.Result]()
	cache := verificationcache.New(resultCache, &verificationcache.InMemoryMetrics{})

	result := runVerify(t, cache, detector)
	require.NotEmpty(t, result.Raw)

	entries := resultCache.Values()
	require.Len(t, entries, 1)
	assert.Empty(t, entries[0].Raw, "the cache must not persist raw secret material")
	assert.Nil(t, entries[0].RawV2)
	assert.Nil(t, entries[0].SecretParts)
	assert.True(t, entries[0].Verified)
}

// TestCustomRegexWebhook_CacheKey_StableAndDistinct covers the CacheKey
// contract directly: stable for an unchanged detector, distinct across
// detector names and verification configurations, and free of secret data.
func TestCustomRegexWebhook_CacheKey_StableAndDistinct(t *testing.T) {
	t.Parallel()

	serverA, _ := countingWebhook(t, http.StatusOK)
	serverB, _ := countingWebhook(t, http.StatusForbidden)

	detectorA := cacheIsolationDetector(t, "alpha", serverA.URL)
	detectorACopy := cacheIsolationDetector(t, "alpha", serverA.URL)
	detectorOtherName := cacheIsolationDetector(t, "beta", serverA.URL)
	detectorOtherEndpoint := cacheIsolationDetector(t, "alpha", serverB.URL)

	// Same name and endpoint, but a different verification configuration:
	// success/rotated ranges and headers must also affect the key.
	detectorOtherConfig, err := NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "alpha",
		Keywords: []string{"token"},
		Regex:    map[string]string{"token": `token="([^"]+)"`},
		Verify: []*custom_detectorspb.VerifierConfig{{
			Endpoint:      serverA.URL,
			Unsafe:        true,
			Headers:       []string{"X-Verifier: alternate"},
			SuccessRanges: []string{"201"},
			RotatedRanges: []string{"401"},
		}},
	})
	require.NoError(t, err)

	keyA, err := detectorA.CacheKey()
	require.NoError(t, err)
	keyACopy, err := detectorACopy.CacheKey()
	require.NoError(t, err)
	keyOtherName, err := detectorOtherName.CacheKey()
	require.NoError(t, err)
	keyOtherEndpoint, err := detectorOtherEndpoint.CacheKey()
	require.NoError(t, err)
	keyOtherConfig, err := detectorOtherConfig.CacheKey()
	require.NoError(t, err)

	assert.Equal(t, keyA, keyACopy, "an unchanged detector must produce a stable key")
	assert.NotEqual(t, keyA, keyOtherName, "detector names must isolate cache entries")
	assert.NotEqual(t, keyA, keyOtherEndpoint, "endpoint changes must isolate cache entries")
	assert.NotEqual(t, keyA, keyOtherConfig, "verification configuration changes must isolate cache entries")
	assert.NotContains(t, string(keyA), "abcdef123456", "the cache key must not contain the secret")
}
