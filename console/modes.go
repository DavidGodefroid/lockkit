package console

import (
	"context"
	"fmt"
	"strings"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ui"
)

// The console's live switches: the clear results (Ctrl-O: the product
// prints the clear result of each masked request here) and unmasked output
// (whether a client may ask for it, each such request then decided on
// lockhub). They change only from the console's own keyboard, Ctrl-O and
// :unmask (or :results), never from a client or a config file, and each
// change is audited. Allowing unmasked output is a typed command confirmed
// with y, never a single key. There is no auto mode: lockhub decides every
// request.

// Key handles a control key pressed in the console.
func (s *Server) Key(k Key) {
	s.lastSeen = s.now()
	if k == KeyCtrlO {
		s.toggleResults()
	}
}

// widenRefused refuses a switch that widens while a decision is being
// asked: the answer or the finger meant for that decision must not decide
// another one nested in it. Narrowing stays allowed.
func (s *Server) widenRefused(what string) bool {
	if s.prompting == 0 {
		return false
	}
	s.println(Paint.Warn(what + ": not while a prompt waits; answer it first"))
	return true
}

// notRecorded tells the human that a widening stays off: its audit record
// could not be written, and a widening takes effect only once recorded.
func (s *Server) notRecorded(what string) {
	s.println(Paint.Fail(what + ": not recorded in the audit log, so it stays off"))
	s.refreshStatus()
}

func (s *Server) toggleResults() {
	if !s.showResults && s.cfg.Level != 0 {
		// Levels 1 and 2: the window is on the agent's desktop, which
		// could read the clear results off it. Nothing is audited: the
		// switch did not move.
		if s.fingerprintLevel() {
			s.println(Paint.Warn("results stay masked at level 2: the window is on the agent's desktop"))
		} else {
			s.println(Paint.Warn("results stay masked at level 1: " + level1Window))
		}
		return
	}
	if !s.showResults && s.widenRefused("clear results") {
		return
	}
	if !s.showResults && s.record(context.Background(), audit.Base{Event: audit.EventResults, Decision: "shown"}) != nil {
		s.notRecorded("clear results")
		return
	}
	s.showResults = !s.showResults
	if !s.showResults {
		_ = s.record(context.Background(), audit.Base{Event: audit.EventResults, Decision: "hidden"})
	}
	if s.showResults {
		msg := word(s.words().ResultsOn, "results: each result is printed here in clear, personal data included; the agent still gets it masked (Ctrl-O: hide)")
		if s.profile.Production {
			s.println(red + ui.MarkWarn + " " + msg + " (PRODUCTION data: mind screen sharing and the terminal's scrollback)" + reset)
		} else {
			s.println(Paint.Warn(msg))
		}
	} else {
		s.println(Paint.OK("results: hidden here; only the masked result leaves, to the agent"))
	}
	s.refreshStatus()
}

func (s *Server) toggleUnmask(ctx context.Context) {
	if s.allowUnmask {
		s.allowUnmask = false
		s.record(context.Background(), audit.Base{Event: audit.EventUnmask, Decision: "off"})
		s.println(Paint.OK(word(s.words().UnmaskOff, "unmask: off; clients get masked output only")))
		s.refreshStatus()
		return
	}
	if s.widenRefused("unmask") {
		return
	}
	warn := word(s.words().UnmaskAsk, "allow clients to ask for unmasked output? Each such request is still approved, never auto-approved")
	if s.profile.Production {
		warn += " (PRODUCTION data)"
	}
	s.println(red + ui.MarkWarn + " " + warn + reset)
	if r := s.decide(ctx, Decision{Prompt: "Allow unmasked output? [y/N] ", Expected: "y", For: "to allow unmasked output"}); r.Outcome != Approved {
		if reason, errText := noFingerFields(r); reason != "" {
			s.record(context.Background(), audit.Base{Event: audit.EventUnmask, Decision: "refused", Reason: reason, Error: errText})
		}
		s.println("unmask: still off")
		return
	}
	if s.record(context.Background(), audit.Base{Event: audit.EventUnmask, Decision: "allowed", Approval: s.approver.Mode()}) != nil {
		s.notRecorded("unmask")
		return
	}
	s.allowUnmask = true
	s.println(red + "unmask: allowed; clients may ask for unmasked output, approved here each time (:unmask: off)" + reset)
	s.refreshStatus()
}

// Command runs a console command typed by the human between requests.
func (s *Server) Command(ctx context.Context, line string) {
	s.lastSeen = s.now()
	switch strings.TrimSpace(line) {
	case "":
	case ":review":
		s.review(ctx)
	case ":status":
		for _, l := range s.statusLines() {
			s.println(l)
		}
	case ":results":
		s.toggleResults()
	case ":unmask":
		s.toggleUnmask(ctx)
	case ":quit":
		s.End("quit")
	default:
		s.println("commands: :review (pending policy change and change requests) · :status · :results (Ctrl-O) · :unmask · :quit")
	}
}

// statusLines is the :status screen.
func (s *Server) statusLines() []string {
	if r, ok := s.cfg.Backend.(StatusRower); ok {
		return keyValues(r.StatusRows(s.statusView()))
	}
	st := s.Status()
	v := s.statusView()
	rows := [][2]string{
		{"profile", fmt.Sprintf("%s · %s · production %t", st.Profile, sanitize.Terminal(s.profile.Where, false), st.Production)},
		{"results", StatusResultsRow(v, Words{})},
		{"unmask", StatusUnmaskRow(v)},
		{"session", fmt.Sprintf("ends in %d min (max_session %s) · idle_timeout %s", st.SessionEndsInS/60, s.profile.MaxSession, s.profile.IdleTimeout)},
		{"policy change", StatusPendingRow(v)},
	}
	for _, l := range s.approved.Describe() {
		rows = append(rows, [2]string{"policy", sanitize.Terminal(l, false)})
	}
	if b := StatusBoundaryRow(v); b != "" {
		rows = append(rows, [2]string{"boundary", b})
	}
	return keyValues(rows)
}

// StatusResultsRow, StatusUnmaskRow, StatusPendingRow and
// StatusBoundaryRow are the values of the console's own :status rows, for
// a StatusRower that keeps them; words (Words.StatusResults) word them.

// StatusModeRow is the value of the former mode row: lockhub decides
// every request.
//
// Deprecated: auto mode is gone and the console's :status has no mode
// row; it goes in the next minor release.
func StatusModeRow(StatusView, Words) string { return "lockhub decides every request" }

// StatusResultsRow is the value of the results row.
func StatusResultsRow(v StatusView, w Words) string {
	results := "masked (the agent's view)"
	if v.ShowResults {
		results = Paint.Yellow(word(w.StatusResults, "shown here in clear, personal data included"))
	}
	return results + Paint.Dim(" (Ctrl-O or :results)")
}

// StatusUnmaskRow is the value of the unmask row.
func StatusUnmaskRow(v StatusView) string {
	unmask := "refused (:unmask allows it)"
	if v.AllowUnmask {
		unmask = Paint.Red("allowed: clients may ask for unmasked output, approved here each time")
	}
	return unmask + Paint.Dim(" (:unmask)")
}

// StatusPendingRow is the value of the policy change row.
func StatusPendingRow(v StatusView) string {
	if v.Pending {
		return Paint.Red("a loosening awaits :review")
	}
	return "none"
}

// StatusBoundaryRow is the value of the boundary row; "" in the session
// shape (no row).
func StatusBoundaryRow(v StatusView) string {
	if v.Boundary != "" && v.Level != 2 {
		return Paint.Red(v.Boundary)
	}
	return v.Boundary
}

// keyValues aligns :status rows.
func keyValues(rows [][2]string) []string {
	width := 0
	for _, r := range rows {
		width = max(width, len(r[0]))
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, "  "+Paint.Dim(r[0]+strings.Repeat(" ", width-len(r[0])))+"  "+r[1])
	}
	return out
}

// statusLine is the text of the status row.
func (s *Server) statusLine() string {
	sep := Paint.Dim(" · ")
	name := strings.ToUpper(s.profile.Name)
	if s.profile.Production {
		name = Paint.Red(name)
	} else {
		name = Paint.Brand(name)
	}
	var suffix string
	var extra []string
	if l, ok := s.cfg.Backend.(StatusLiner); ok {
		suffix, extra = l.StatusLineParts(s.statusView())
	}
	if suffix != "" {
		name += " " + suffix
	}
	parts := []string{name}
	results := Paint.Dim("masked")
	if s.showResults {
		results = Paint.Yellow("clear")
	}
	parts = append(parts, "results "+results+" "+Paint.Dim("^O"))
	if s.allowUnmask {
		parts = append(parts, Paint.Red("unmask allowed"))
	}
	parts = append(parts, extra...)
	if s.cfg.Boundary != "" && !s.fingerprintLevel() {
		parts = append(parts, Paint.Red("level 1: desktop boundary"))
	}
	if s.pending != nil {
		parts = append(parts, Paint.Red("policy change pending")+" "+Paint.Dim(":review"))
	}
	if n := len(s.requests); n > 0 {
		plural := "s"
		if n == 1 {
			plural = ""
		}
		parts = append(parts, fmt.Sprintf("%d change request%s", n, plural)+" "+Paint.Dim(":review"))
	}
	return strings.Join(parts, sep)
}

func (s *Server) refreshStatus() {
	if st, ok := s.cfg.IO.(StatusLine); ok {
		st.SetStatus(s.statusLine())
	}
}

func (s *Server) clearStatus() {
	if st, ok := s.cfg.IO.(StatusLine); ok {
		st.SetStatus("")
	}
}
