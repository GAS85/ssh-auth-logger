package main

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newCleanupTestCache builds a cache without the background cleanup goroutine, so tests decide when cleanup() runs. ages maps a key to how long ago it was last used.
func newCleanupTestCache(ttl time.Duration, ages map[string]time.Duration) *hostKeyCache {
	c := &hostKeyCache{
		keys:         make(map[string]cachedHostKey),
		ttl:          ttl,
		cleanupEvery: time.Hour,
	}
	now := time.Now()
	for k, age := range ages {
		c.keys[k] = cachedHostKey{lastUsed: now.Add(-age)}
	}
	return c
}

func cacheKeyNames(c *hostKeyCache) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	names := make([]string, 0, len(c.keys))
	for k := range c.keys {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func assertCacheKeys(t *testing.T, c *hostKeyCache, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := cacheKeyNames(c)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("cache keys = %v, want %v", got, want)
	}
}

// captureDebugLog records everything logged through the standard logger, including debug entries, and keeps the output quiet.
func captureDebugLog(t *testing.T) *logHook {
	t.Helper()

	std := logrus.StandardLogger()
	oldLevel, oldOut := std.GetLevel(), std.Out

	hook := &logHook{}
	std.SetLevel(logrus.DebugLevel)
	std.SetOutput(io.Discard)
	std.AddHook(hook)

	t.Cleanup(func() {
		std.ReplaceHooks(logrus.LevelHooks{})
		std.SetLevel(oldLevel)
		std.SetOutput(oldOut)
	})
	return hook
}

const cleanupLogMessage = "SSH host key cache cleanup completed"

func cleanupLogEntries(h *logHook) []*logrus.Entry {
	var out []*logrus.Entry
	for _, e := range h.Entries {
		if e.Message == cleanupLogMessage {
			out = append(out, e)
		}
	}
	return out
}

// ── cleanup ──────────────────────────────────────────────────────────────────

func TestHostKeyCacheCleanup_RemovesExpiredKeepsFresh(t *testing.T) {
	c := newCleanupTestCache(time.Hour, map[string]time.Duration{
		"old:rsa":     2 * time.Hour,
		"older:ed":    48 * time.Hour,
		"fresh:ed":    0,
		"recent:rsa":  10 * time.Minute,
		"almost:rsa":  59 * time.Minute,
		"expired:rsa": 61 * time.Minute,
	})

	c.cleanup()

	assertCacheKeys(t, c, "fresh:ed", "recent:rsa", "almost:rsa")
}

func TestHostKeyCacheCleanup_KeepsEverythingWithinTTL(t *testing.T) {
	c := newCleanupTestCache(time.Hour, map[string]time.Duration{
		"a": 0,
		"b": time.Minute,
		"c": 30 * time.Minute,
	})
	hook := captureDebugLog(t)

	c.cleanup()

	assertCacheKeys(t, c, "a", "b", "c")
	if n := len(cleanupLogEntries(hook)); n != 0 {
		t.Errorf("nothing was removed, but %d cleanup log entries were written", n)
	}
}

func TestHostKeyCacheCleanup_RemovesEverythingWhenAllExpired(t *testing.T) {
	c := newCleanupTestCache(time.Minute, map[string]time.Duration{
		"a": time.Hour,
		"b": 24 * time.Hour,
	})

	c.cleanup()

	assertCacheKeys(t, c)
	if c.keys == nil {
		t.Error("the map must stay usable (non-nil) after cleanup")
	}
}

func TestHostKeyCacheCleanup_EmptyCache(t *testing.T) {
	c := newCleanupTestCache(time.Hour, nil)
	hook := captureDebugLog(t)

	c.cleanup() // must not panic

	assertCacheKeys(t, c)
	if n := len(cleanupLogEntries(hook)); n != 0 {
		t.Errorf("empty cache produced %d cleanup log entries", n)
	}
}

func TestHostKeyCacheCleanup_UsesConfiguredTTL(t *testing.T) {
	ages := map[string]time.Duration{"idle-10m": 10 * time.Minute}

	short := newCleanupTestCache(5*time.Minute, ages)
	short.cleanup()
	assertCacheKeys(t, short)

	long := newCleanupTestCache(time.Hour, ages)
	long.cleanup()
	assertCacheKeys(t, long, "idle-10m")
}

func TestHostKeyCacheCleanup_DoesNotTouchRemainingEntries(t *testing.T) {
	c := newCleanupTestCache(time.Hour, map[string]time.Duration{
		"keep": 30 * time.Minute,
		"drop": 2 * time.Hour,
	})
	before := c.keys["keep"]

	c.cleanup()

	// Cleanup must not count as "use", otherwise keys would never expire.
	if after := c.keys["keep"]; !after.lastUsed.Equal(before.lastUsed) {
		t.Errorf("lastUsed changed from %v to %v", before.lastUsed, after.lastUsed)
	}
}

func TestHostKeyCacheCleanup_IsIdempotent(t *testing.T) {
	c := newCleanupTestCache(time.Hour, map[string]time.Duration{
		"keep": time.Minute,
		"drop": 2 * time.Hour,
	})
	hook := captureDebugLog(t)

	c.cleanup()
	c.cleanup()

	assertCacheKeys(t, c, "keep")
	if n := len(cleanupLogEntries(hook)); n != 1 {
		t.Errorf("only the first run removes something, got %d log entries", n)
	}
}

func TestHostKeyCacheCleanup_LogsRemovedAndRemaining(t *testing.T) {
	c := newCleanupTestCache(time.Hour, map[string]time.Duration{
		"drop-1": 2 * time.Hour,
		"drop-2": 3 * time.Hour,
		"keep":   time.Minute,
	})
	hook := captureDebugLog(t)

	c.cleanup()

	entries := cleanupLogEntries(hook)
	if len(entries) != 1 {
		t.Fatalf("got %d cleanup log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Level != logrus.DebugLevel {
		t.Errorf("level = %v, want debug", e.Level)
	}
	if e.Data["removed"] != 2 {
		t.Errorf("removed = %v, want 2", e.Data["removed"])
	}
	if e.Data["remaining"] != 1 {
		t.Errorf("remaining = %v, want 1", e.Data["remaining"])
	}
	if e.Data["product"] != appName {
		t.Errorf("entry should carry the common fields, product = %v", e.Data["product"])
	}
}

// The cleanup log is debug-level: it must stay silent at the default (info) level.
func TestHostKeyCacheCleanup_SilentAtInfoLevel(t *testing.T) {
	c := newCleanupTestCache(time.Hour, map[string]time.Duration{"drop": 2 * time.Hour})

	var buf bytes.Buffer
	std := logrus.StandardLogger()
	oldLevel, oldOut := std.GetLevel(), std.Out
	std.SetLevel(logrus.InfoLevel)
	std.SetOutput(&buf)
	defer func() { std.SetLevel(oldLevel); std.SetOutput(oldOut) }()

	c.cleanup()

	assertCacheKeys(t, c)
	if buf.Len() != 0 {
		t.Errorf("unexpected output at info level: %q", buf.String())
	}
}

// Cleanup runs on a timer while connections read and write the cache. Run with -race.
func TestHostKeyCacheCleanup_ConcurrentWithCacheAccess(t *testing.T) {
	c := newCleanupTestCache(time.Hour, nil)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c.mu.Lock()
				c.keys[fmt.Sprintf("g%d-%d", g, i)] = cachedHostKey{lastUsed: time.Now().Add(-2 * time.Hour)}
				c.mu.Unlock()
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			c.cleanup()
		}
	}()
	wg.Wait()

	c.cleanup()
	assertCacheKeys(t, c)
}

// ── cleanup together with getHostKeySigner ───────────────────────────────────

// useCache swaps the global host key cache for the duration of a test.
func useCache(t *testing.T, c *hostKeyCache) {
	t.Helper()
	old := hostKeys
	hostKeys = c
	t.Cleanup(func() { hostKeys = old })
}

func backdate(c *hostKeyCache, key string, age time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.keys[key]
	entry.lastUsed = time.Now().Add(-age)
	c.keys[key] = entry
}

// Using a key (as every connection does) must keep it alive through cleanup.
func TestHostKeyCacheCleanup_RecentlyUsedKeySurvives(t *testing.T) {
	c := newCleanupTestCache(time.Hour, nil)
	useCache(t, c)

	if _, err := getHostKeySigner("survivor", "ed25519"); err != nil {
		t.Fatal(err)
	}
	backdate(c, "survivor:ed25519", 2*time.Hour)                       // would be evicted ...
	if _, err := getHostKeySigner("survivor", "ed25519"); err != nil { // ... but is used again
		t.Fatal(err)
	}

	c.cleanup()

	assertCacheKeys(t, c, "survivor:ed25519")
}

// Evicting a key must not change the host key a returning attacker sees: it is derived from the host name and SSHD_KEY_KEY.
func TestHostKeyCacheCleanup_EvictedKeyIsRegeneratedIdentically(t *testing.T) {
	c := newCleanupTestCache(time.Hour, nil)
	useCache(t, c)

	first, err := getHostKeySigner("returning-host", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	backdate(c, "returning-host:ed25519", 2*time.Hour)

	c.cleanup()
	assertCacheKeys(t, c)

	second, err := getHostKeySigner("returning-host", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKey().Marshal(), second.PublicKey().Marshal()) {
		t.Error("host key changed after cache eviction")
	}
	assertCacheKeys(t, c, "returning-host:ed25519")
}

func TestHostKeyCacheCleanup_OnlyExpiredHostsAreEvicted(t *testing.T) {
	c := newCleanupTestCache(time.Hour, nil)
	useCache(t, c)

	for _, host := range []string{"host-a", "host-b", "host-c"} {
		if _, err := getHostKeySigner(host, "ed25519"); err != nil {
			t.Fatal(err)
		}
	}
	backdate(c, "host-a:ed25519", 3*time.Hour)
	backdate(c, "host-c:ed25519", 90*time.Minute)

	c.cleanup()

	assertCacheKeys(t, c, "host-b:ed25519")
}

// ── cleanupLoop ──────────────────────────────────────────────────────────────

// The background loop started by newHostKeyCache must actually call cleanup().
func TestHostKeyCache_CleanupLoopEvictsExpiredKeys(t *testing.T) {
	// The loop has no stop mechanism, so this cache lives until the test binary exits. A 20ms tick keeps the overhead negligible.
	c := newHostKeyCache(time.Hour, 20*time.Millisecond)

	c.mu.Lock()
	c.keys["stale"] = cachedHostKey{lastUsed: time.Now().Add(-2 * time.Hour)}
	c.keys["fresh"] = cachedHostKey{lastUsed: time.Now()}
	c.mu.Unlock()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.RLock()
		_, staleLeft := c.keys["stale"]
		c.mu.RUnlock()
		if !staleLeft {
			assertCacheKeys(t, c, "fresh")
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cleanupLoop did not evict the expired key within 3s")
}
