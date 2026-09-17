package delivery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
	"github.com/KazuhaHub/AlertHub/server/internal/store"
)

// fakeSender fails its first failN Send calls, then succeeds; counts calls.
type fakeSender struct {
	mu      sync.Mutex
	failN   int
	calls   int
	targets []string
}

func (f *fakeSender) Channel() string               { return "test" }
func (f *fakeSender) Targets(*alert.Alert) []string { return f.targets }
func (f *fakeSender) Send(context.Context, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failN {
		return errors.New("transient boom")
	}
	return nil
}
func (f *fakeSender) callCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func tempStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/d.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mkAlert(id string) *alert.Alert {
	return &alert.Alert{ID: id, Category: "system", Severity: "warning", Title: "t"}
}

// Clock-driven (no sleeps): a transient sender that fails twice then succeeds must
// end 'sent' after exactly 3 attempts, and backoff must gate retries until due.
func TestDelivery_RetryThenSuccess(t *testing.T) {
	st := tempStore(t)
	fs := &fakeSender{failN: 2, targets: []string{"t1"}}
	base := time.Unix(1_000_000, 0)
	m := New(st, Config{MaxAttempts: 5, BaseBackoff: 10 * time.Second, MaxBackoff: 1000 * time.Second, Lease: 60 * time.Second, Batch: 10}, fs)
	m.now = func() time.Time { return base }
	ctx := context.Background()

	m.Enqueue(mkAlert("a1"), 1, "{}")

	if n := m.processBatch(ctx, base); n != 1 { // attempt 1 → fail → backoff to base+10s
		t.Fatalf("batch1 claimed %d, want 1", n)
	}
	if n := m.processBatch(ctx, base); n != 0 { // not due yet (backoff gate)
		t.Fatalf("batch claimed %d before backoff, want 0", n)
	}
	if n := m.processBatch(ctx, base.Add(10*time.Second)); n != 1 { // attempt 2 → fail → +20s
		t.Fatalf("batch2 claimed %d, want 1", n)
	}
	if n := m.processBatch(ctx, base.Add(30*time.Second)); n != 1 { // attempt 3 → success
		t.Fatalf("batch3 claimed %d, want 1", n)
	}

	if got := fs.callCount(); got != 3 {
		t.Fatalf("sender called %d times, want 3", got)
	}
	assertStatus(t, st, map[string]int{"sent": 1})
}

// A permanently-failing sender must dead-letter after exactly MaxAttempts.
func TestDelivery_DeadLetter(t *testing.T) {
	st := tempStore(t)
	fs := &fakeSender{failN: 1000, targets: []string{"t1"}}
	base := time.Unix(2_000_000, 0)
	m := New(st, Config{MaxAttempts: 2, BaseBackoff: 10 * time.Second, MaxBackoff: 1000 * time.Second, Lease: 60 * time.Second, Batch: 10}, fs)
	m.now = func() time.Time { return base }
	ctx := context.Background()

	m.Enqueue(mkAlert("a2"), 1, "{}")
	m.processBatch(ctx, base)                     // attempt 1 → fail → reschedule
	m.processBatch(ctx, base.Add(10*time.Second)) // attempt 2 → fail → dead (2>=2)

	if got := fs.callCount(); got != 2 {
		t.Fatalf("sender called %d times, want 2", got)
	}
	assertStatus(t, st, map[string]int{"dead": 1})
}

// Enqueuing the same (alert, channel, target) twice must create only one job.
func TestDelivery_IdempotentEnqueue(t *testing.T) {
	st := tempStore(t)
	fs := &fakeSender{failN: 0, targets: []string{"t1"}}
	base := time.Unix(3_000_000, 0)
	m := New(st, Config{Batch: 10}, fs)
	m.now = func() time.Time { return base }

	m.Enqueue(mkAlert("a3"), 1, "{}")
	m.Enqueue(mkAlert("a3"), 1, "{}") // duplicate
	assertStatus(t, st, map[string]int{"pending": 1})
}

// End-to-end through the real WebhookSender + RunWorker goroutine against an
// httptest server that 500s twice then 200s — proves the live loop delivers.
func TestDelivery_WebhookIntegration(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	st := tempStore(t)
	m := New(st, Config{
		MaxAttempts: 5, BaseBackoff: 20 * time.Millisecond, MaxBackoff: 100 * time.Millisecond,
		Lease: 2 * time.Second, Batch: 10, PollInterval: 10 * time.Millisecond,
	}, NewWebhookSender([]string{srv.URL}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.RunWorker(ctx)
	m.Enqueue(mkAlert("wh1"), 1, `{"id":"wh1"}`)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, _ := st.CountDeliveriesByStatus(); c["sent"] == 1 {
			if got := atomic.LoadInt32(&hits); got >= 3 {
				return // delivered after retrying past the two 500s
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	c, _ := st.CountDeliveriesByStatus()
	t.Fatalf("webhook not delivered: status=%v hits=%d", c, atomic.LoadInt32(&hits))
}

// Same retry-then-success scenario against real PostgreSQL — exercises the
// FOR UPDATE SKIP LOCKED + RETURNING claim path. Gated on ALERTHUB_TEST_PG_DSN.
func TestDelivery_Postgres(t *testing.T) {
	dsn := os.Getenv("ALERTHUB_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set ALERTHUB_TEST_PG_DSN to run the Postgres delivery test")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	defer st.Close()

	fs := &fakeSender{failN: 2, targets: []string{"pg-t1"}}
	base := time.Unix(5_000_000, 0)
	m := New(st, Config{MaxAttempts: 5, BaseBackoff: 10 * time.Second, MaxBackoff: 1000 * time.Second, Lease: 60 * time.Second, Batch: 10}, fs)
	m.now = func() time.Time { return base }
	ctx := context.Background()

	// Unique alert id per run so the idempotency index doesn't make a rerun against
	// a non-fresh DB a no-op (enqueue would ON CONFLICT DO NOTHING → 0 jobs → flake).
	alertID := "pg-a" + strconv.FormatInt(time.Now().UnixNano(), 10)
	m.Enqueue(mkAlert(alertID), 1, "{}")
	m.processBatch(ctx, base)                     // attempt 1 → fail
	m.processBatch(ctx, base.Add(10*time.Second)) // attempt 2 → fail
	m.processBatch(ctx, base.Add(30*time.Second)) // attempt 3 → success

	if got := fs.callCount(); got != 3 {
		t.Fatalf("PG: sender called %d times, want 3", got)
	}
	if c, _ := st.CountDeliveriesByStatus(); c["sent"] < 1 {
		t.Fatalf("PG: want >=1 sent, got %v", c)
	}
}

func assertStatus(t *testing.T, st *store.Store, want map[string]int) {
	t.Helper()
	got, err := st.CountDeliveriesByStatus()
	if err != nil {
		t.Fatalf("CountDeliveriesByStatus: %v", err)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("status %q = %d, want %d (full: %v)", k, got[k], v, got)
		}
	}
}
