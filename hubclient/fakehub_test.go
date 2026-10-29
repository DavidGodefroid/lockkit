package hubclient_test

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

// fakeHub speaks lockhub's lock API v1: signed requests, tickets,
// decisions with a cursor.
type fakeHub struct {
	t        *testing.T
	instance string
	lockPub  ed25519.PublicKey
	hubPub   ed25519.PublicKey
	hubPriv  ed25519.PrivateKey

	mu        sync.Mutex
	nonces    map[string]bool
	tickets   map[string][]byte
	pushes    int // POST /v1/tickets accepted
	withdrawn map[string]string
	consumed  map[string]bool
	decisions []item
	sinces    []string // since values the lock sent
	status    int      // forced status for POST /v1/tickets, 0 none
	srv       *httptest.Server
}

type item struct {
	Seq      int64           `json:"seq"`
	Ticket   string          `json:"ticket"`
	Decision json.RawMessage `json:"decision"`
}

func newFakeHub(t *testing.T, instance string, lockPub ed25519.PublicKey) *fakeHub {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := &fakeHub{t: t, instance: instance, lockPub: lockPub, hubPub: pub, hubPriv: priv,
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *fakeHub) auth(next func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
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

func (h *fakeHub) push(w http.ResponseWriter, r *http.Request, body []byte) {
	if h.status != 0 {
		writeJSON(w, h.status, map[string]string{"error": "forced", "message": "forced by the test"})
		return
	}
	tk, err := ticket.VerifyTicket(h.lockPub, body)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad_ticket", "message": err.Error()})
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

func (h *fakeHub) list(w http.ResponseWriter, r *http.Request, _ []byte) {
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

// decide records a decision on ticket id signed with key (the hub's when
// nil).
func (h *fakeHub) decide(id string, out ticket.Outcome, reason string, key ed25519.PrivateKey) {
	h.t.Helper()
	h.decideWith(id, out, reason, key, nil)
}

// decideWith is decide with mod applied to the decision before signing.
func (h *fakeHub) decideWith(id string, out ticket.Outcome, reason string, key ed25519.PrivateKey, mod func(*ticket.Decision)) {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	raw, ok := h.tickets[id]
	if !ok {
		h.t.Fatalf("decide: no ticket %s", id)
	}
	var tk ticket.Ticket
	if err := json.Unmarshal(raw, &tk); err != nil {
		h.t.Fatal(err)
	}
	if key == nil {
		key = h.hubPriv
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

func (h *fakeHub) pushed() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pushes
}

func (h *fakeHub) ticket(id string) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tickets[id]
}
