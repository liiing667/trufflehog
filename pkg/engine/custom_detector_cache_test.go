package engine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache"
)

// TestEngine_CustomDetectorsVerificationCacheIsolated runs two custom
// detectors that share DetectorType_CustomRegex and match the same token,
// each backed by its own offline webhook, with a verification result cache
// enabled. Before the fix both detectors produced the same cache key (Raw +
// DetectorType only), so the second detector reused the first detector's
// Verified status and never contacted its own webhook.
func TestEngine_CustomDetectorsVerificationCacheIsolated(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "custom-cache-isolation")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_, err = tmpFile.WriteString("test stuff")
	require.NoError(t, err)

	var webhookOneHits, webhookTwoHits int64
	webhookOne := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&webhookOneHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookOne.Close()
	webhookTwo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&webhookTwoHits, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer webhookTwo.Close()

	detectorOne, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector one",
		Keywords: []string{"test"},
		Regex:    map[string]string{"test": "\\w+"},
		Verify:   []*custom_detectorspb.VerifierConfig{{Endpoint: webhookOne.URL, Unsafe: true, SuccessRanges: []string{"200"}}},
	})
	require.NoError(t, err)

	detectorTwo, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector two",
		Keywords: []string{"test"},
		Regex:    map[string]string{"test": "\\w+"},
		Verify:   []*custom_detectorspb.VerifierConfig{{Endpoint: webhookTwo.URL, Unsafe: true, SuccessRanges: []string{"200"}}},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sourceManager := sources.NewManager(
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(64),
	)

	conf := Config{
		Concurrency:              1,
		Decoders:                 decoders.DefaultDecoders(),
		Detectors:                []detectors.Detector{detectorOne, detectorTwo},
		Verify:                   true,
		SourceManager:            sourceManager,
		Dispatcher:               NewPrinterDispatcher(new(discardPrinter)),
		VerificationResultCache:  simple.NewCache[detectors.Result](),
		VerificationCacheMetrics: &verificationcache.InMemoryMetrics{},
	}

	engine, err := NewEngine(ctx, &conf)
	require.NoError(t, err)
	engine.Start(ctx)

	_, err = engine.ScanFileSystem(ctx, sources.FilesystemConfig{Paths: []string{tmpFile.Name()}})
	require.NoError(t, err)
	require.NoError(t, engine.Finish(ctx))

	metrics := engine.GetMetrics()

	// Each detector matches two words in "test stuff"; with a shared,
	// un-isolated cache the second detector would inherit the first
	// detector's verified verdict and never call its webhook.
	assert.Equal(t, uint64(2), metrics.VerifiedSecretsFound,
		"only the detector whose webhook returns 200 should have verified secrets")
	assert.Equal(t, int64(2), atomic.LoadInt64(&webhookOneHits),
		"the first webhook verifies both of its matches")
	assert.Equal(t, int64(2), atomic.LoadInt64(&webhookTwoHits),
		"the second webhook must be contacted independently despite the shared DetectorType")
}

// TestEngine_CustomDetectorsVerificationCacheSameDetectorRepeats verifies the
// other half of the contract: the same detector reuses cached verdicts for a
// repeated chunk rather than re-contacting its webhook. The two detectChunk
// calls are sequential so the cache is observably populated before the repeat.
func TestEngine_CustomDetectorsVerificationCacheSameDetectorRepeats(t *testing.T) {
	var webhookHits int64
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&webhookHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	detector, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "repeating detector",
		Keywords: []string{"test"},
		Regex:    map[string]string{"test": "\\w+"},
		Verify:   []*custom_detectorspb.VerifierConfig{{Endpoint: webhook.URL, Unsafe: true, SuccessRanges: []string{"200"}}},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	engine := &Engine{
		results:           make(chan detectors.ResultWithMetadata, 8),
		verificationCache: verificationcache.New(simple.NewCache[detectors.Result](), &verificationcache.InMemoryMetrics{}),
	}
	ahcore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{detector})
	matches := ahcore.FindDetectorMatches([]byte("test stuff"))
	require.Len(t, matches, 1)

	chunk := detectableChunk{
		detector: matches[0],
		verify:   true,
		wgDoneFn: func() {},
	}
	chunk.chunk.Data = []byte("test stuff")

	engine.detectChunk(ctx, chunk)
	engine.detectChunk(ctx, chunk)
	close(engine.results)

	var results []detectors.ResultWithMetadata
	for r := range engine.results {
		results = append(results, r)
	}
	require.Len(t, results, 4, "each pass produces the two word matches")

	assert.Equal(t, int64(2), atomic.LoadInt64(&webhookHits),
		"only the first pass's two matches should contact the webhook")

	var fromCache int
	for _, r := range results {
		assert.True(t, r.Verified)
		if r.VerificationFromCache {
			fromCache++
		}
	}
	assert.Equal(t, 2, fromCache, "the repeat must be served from the cache")
}
