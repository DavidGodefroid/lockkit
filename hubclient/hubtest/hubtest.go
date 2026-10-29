// Package hubtest is a fake lockhub for the tests of locks: it speaks the
// lock API v1 (signed requests, tickets, decisions with a cursor) on an
// httptest server, and lets a test decide tickets.
package hubtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// Hub is a fake lockhub serving one lock instance.
type Hub struct {
	t        testing.TB
	instance string
	// Pub and Priv are the hub's key; a lock pins Pub.
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
	srv  *httptest.Server

	mu        sync.Mutex
	lockPub   ed25519.PublicKey
	nonces    map[string]bool
	tickets   map[string][]byte
	pushes    int
	withdrawn map[string]string
	consumed  map[string]bool
	decisions []item
	sinces    []string
	status    int
}

type item struct {
	Seq      int64           `json:"seq"`
	Ticket   string          `json:"ticket"`
	Decision json.RawMessage `json:"decision"`
}

// New starts a hub for instance, whose pinned lock key is lockPub. It
// stops with the test.
func New(t testing.TB, instance string, lockPub ed25519.PublicKey) *Hub {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := &Hub{t: t, instance: instance, lockPub: lockPub, Pub: pub, Priv: priv,
		nonces: map[string]bool{}, tickets: map[string][]byte{}, withdrawn: map[string]string{}, consumed: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hello", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"name": "lockhub", "version": "test", "api": 1})
	})
	mux.HandleFunc("POST /v1/tickets", h.auth(h.push))
	mux.HandleFunc("POST /v1/tickets/{id}/withdraw", h.auth(func(w http.ResponseWriter, r *http.Request, body []byte) {
		var req struct{ Reason string }
		_ = json.Unmarshal(body, &req)
		h.withdrawn[r.PathValue("id")] = req.Reason
		w.WriteHeader(204)
	}))
	mux.HandleFunc("POST /v1/tickets/{id}/consumed", h.auth(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		h.consumed[r.PathValue("id")] = true
		w.WriteHeader(204)
	}))
	mux.HandleFunc("GET /v1/decisions", h.auth(h.list))
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// URL is the hub's base URL.
func (h *Hub) URL() string { return h.srv.URL }

// Close stops the hub (it becomes unreachable).
func (h *Hub) Close() { h.srv.Close() }

// SetLockKey changes the lock key the hub pinned for the instance.
func (h *Hub) SetLockKey(pub ed25519.PublicKey) { h.mu.Lock(); h.lockPub = pub; h.mu.Unlock() }

// SetPushStatus makes every POST /v1/tickets answer code (0: normal).
func (h *Hub) SetPushStatus(code int) { h.mu.Lock(); h.status = code; h.mu.Unlock() }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Hub) auth(next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		inst, ts, nonce, sig := r.Header.Get("Lock-Instance"), r.Header.Get("Lock-Time"), r.Header.Get("Lock-Nonce"), r.Header.Get("Lock-Sig")
		sec, err := strconv.ParseInt(ts, 10, 64)
		h.mu.Lock()
		defer h.mu.Unlock()
		switch {
		case inst != h.instance || err != nil || len(nonce) < 16:
			writeJSON(w, 401, map[string]string{"error": "unauthorized", "message": "malformed"})
		case ticket.VerifyBytes(h.lockPub, ticket.ContextRequest,
			ticket.RequestMessage(r.Method, r.URL.RequestURI(), inst, time.Unix(sec, 0), nonce, body), sig) != nil:
			writeJSON(w, 401, map[string]string{"error": "unauthorized", "message": "request signature does not verify"})
		case h.nonces[nonce]:
			writeJSON(w, 401, map[string]string{"error": "replay", "message": "nonce used"})
		default:
			h.nonces[nonce] = true
			next(w, r, body)
		}
	}
}

func (h *Hub) push(w http.ResponseWriter, r *http.Request, body []byte) {
	if h.status != 0 {
		writeJSON(w, h.status, map[string]string{"error": "forced", "message": "forced by the test"})
		return
	}
	tk, err := ticket.VerifyTicket(h.lockPub, body)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad_ticket", "message": err.Error()})
		return
	}
	if tk.Source.Instance != h.instance {
		writeJSON(w, 403, map[string]string{"error": "forbidden", "message": "ticket for another instance"})
		return
	}
	if old, ok := h.tickets[tk.ID]; ok {
		if string(old) != string(body) {
			writeJSON(w, 409, map[string]string{"error": "conflict", "message": "other content"})
			return
		}
		writeJSON(w, 200, map[string]any{"ticket": tk.ID, "created": false})
		return
	}
	h.tickets[tk.ID] = body
	h.pushes++
	writeJSON(w, 201, map[string]any{"ticket": tk.ID, "created": true})
}

func (h *Hub) list(w http.ResponseWriter, r *http.Request, _ []byte) {
	h.sinces = append(h.sinces, r.URL.Query().Get("since"))
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	res := struct {
		Decisions []item `json:"decisions"`
		Cursor    int64  `json:"cursor"`
	}{Decisions: []item{}, Cursor: since}
	for _, d := range h.decisions {
		if d.Seq > since {
			res.Decisions = append(res.Decisions, d)
			res.Cursor = d.Seq
		}
	}
	writeJSON(w, 200, res)
}

// Decide records a decision on ticket id, signed with the hub's key.
func (h *Hub) Decide(id string, out ticket.Outcome, reason string) {
	h.t.Helper()
	h.DecideWith(id, out, reason, nil, nil)
}

// DecideWith is Decide signed with key (nil: the hub's), mod applied to
// the decision before signing (nil: none).
func (h *Hub) DecideWith(id string, out ticket.Outcome, reason string, key ed25519.PrivateKey, mod func(*ticket.Decision)) {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	raw, ok := h.tickets[id]
	if !ok {
		h.t.Fatalf("hubtest: no ticket %s", id)
	}
	var tk ticket.Ticket
	if err := json.Unmarshal(raw, &tk); err != nil {
		h.t.Fatal(err)
	}
	if key == nil {
		key = h.Priv
	}
	d := &ticket.Decision{V: ticket.Version, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
		PlanHash: tk.PlanHash, Decision: out, Reason: reason, Approver: ticket.Approver{ID: "host:uid:1000"},
		Facade: "tty", At: time.Now().UTC().Truncate(time.Millisecond), Nonce: ticket.NewNonce()}
	if mod != nil {
		mod(d)
	}
	if err := d.Sign(key); err != nil {
		h.t.Fatal(err)
	}
	b, _ := d.Marshal()
	h.decisions = append(h.decisions, item{Seq: int64(len(h.decisions) + 1), Ticket: id, Decision: b})
}

// Pushed is how many tickets the hub accepted.
func (h *Hub) Pushed() int { h.mu.Lock(); defer h.mu.Unlock(); return h.pushes }

// Ticket is the signed ticket id as pushed, nil when not.
func (h *Hub) Ticket(id string) []byte { h.mu.Lock(); defer h.mu.Unlock(); return h.tickets[id] }

// Tickets lists the ids of the tickets pushed.
func (h *Hub) Tickets() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var ids []string
	for id := range h.tickets {
		ids = append(ids, id)
	}
	return ids
}

// Consumed reports whether the lock said ticket id was consumed.
func (h *Hub) Consumed(id string) bool { h.mu.Lock(); defer h.mu.Unlock(); return h.consumed[id] }

// Withdrawn returns the reason ticket id was withdrawn with, and whether.
func (h *Hub) Withdrawn(id string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.withdrawn[id]
	return r, ok
}

// Sinces lists the since values of the lock's decision polls.
func (h *Hub) Sinces() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.sinces...)
}
