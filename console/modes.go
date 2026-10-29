package console

import (
	"context"
	"fmt"
	"strings"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ui"
)

// The console's live switches: the approval mode (manual, where every
// request is prompted, or auto, where requests run without a prompt unless
// their screen says NeverAuto), the clear results (Ctrl-O: the product
// prints the clear result of each masked request here) and unmasked output
// (whether a client may ask for it, each such request then approved here).
// They change only from the console's own keyboard, Shift+Tab, Ctrl-O and
// :unmask (or :mode and :results), never from a client or a config file,
// and each change is audited. A production profile stays in manual mode.
// Allowing unmasked output is a typed command confirmed with y, never a
// single key.

// autoApprove reports whether auto mode is in effect: never on a
// production profile.
func (s *Server) autoApprove() bool { return s.auto && !s.profile.Production }

func (s *Server) modeName() string {
	if s.autoApprove() {
		return "auto"
	}
	return "manual"
}

// Key handles a control key pressed in the console.
func (s *Server) Key(k Key) {
	s.lastSeen = s.now()
	switch k {
	case KeyShiftTab:
		s.toggleMode()
	case KeyCtrlO:
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

func (s *Server) toggleMode() {
	if s.profile.Production {
		s.println(Paint.Warn("auto mode is not available on a production profile: every request is prompted"))
		return
	}
	if !s.auto && s.widenRefused("auto mode") {
		return
	}
	if !s.auto && s.fingerprintLevel() {
		// Level 2: auto mode widens what runs unprompted, so a typed
		// answer alone, which the agent could type too, never turns it on.
		if r := s.decide(context.Background(), Decision{Prompt: "Switch to auto mode? [y/N] ", Expected: "y", For: "to switch to auto mode"}); r.Outcome != Approved {
			if reason, errText := noFingerFields(r); reason != "" {
				s.record(context.Background(),audit.Base{Event: audit.EventMode, Decision: "refused", Reason: reason, Error: errText})
			}
			s.println("mode: still manual")
			s.refreshStatus()
			return
		}
	}
	s.auto = !s.auto
	s.record(context.Background(),audit.Base{Event: audit.EventMode, Decision: s.modeName()})
	if s.auto {
		s.println(Paint.Yellow(ui.MarkWarn + " auto mode: requests run without a prompt; those that ask for a human every time are still prompted (Shift+Tab: back to manual)"))
	} else {
		s.println(Paint.OK("manual mode: every request is prompted"))
	}
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
	s.showResults = !s.showResults
	decision := "hidden"
	if s.showResults {
		decision = "shown"
	}
	s.record(context.Background(),audit.Base{Event: audit.EventResults, Decision: decision})
	if s.showResults {
		msg := "results: each result is printed here in clear, personal data included; the agent still gets it masked (Ctrl-O: hide)"
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
		s.record(context.Background(),audit.Base{Event: audit.EventUnmask, Decision: "off"})
		s.println(Paint.OK("unmask: off; clients get masked output only"))
		s.refreshStatus()
		return
	}
	if s.widenRefused("unmask") {
		return
	}
	warn := "allow clients to ask for unmasked output? Each such request is still approved here, never auto-approved"
	if s.profile.Production {
		warn += " (PRODUCTION data)"
	}
	s.println(red + ui.MarkWarn + " " + warn + reset)
	if r := s.decide(ctx, Decision{Prompt: "Allow unmasked output? [y/N] ", Expected: "y", For: "to allow unmasked output"}); r.Outcome != Approved {
		if reason, errText := noFingerFields(r); reason != "" {
			s.record(context.Background(),audit.Base{Event: audit.EventUnmask, Decision: "refused", Reason: reason, Error: errText})
		}
		s.println("unmask: still off")
		return
	}
	s.allowUnmask = true
	s.record(context.Background(),audit.Base{Event: audit.EventUnmask, Decision: "allowed", Approval: s.approver.Mode()})
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
	case ":mode":
		s.toggleMode()
	case ":results":
		s.toggleResults()
	case ":unmask":
		s.toggleUnmask(ctx)
	case ":quit":
		s.End("quit")
	default:
		s.println("commands: :review (pending policy change and change requests) · :status · :mode (Shift+Tab) · :results (Ctrl-O) · :unmask · :quit")
	}
}

// statusLines is the :status screen.
func (s *Server) statusLines() []string {
	st := s.Status()
	mode := "manual: every request is prompted"
	switch {
	case s.autoApprove():
		mode = Paint.Yellow("auto: requests run without a prompt unless they ask for a human every time")
	case s.profile.Production:
		mode += " (production: auto mode unavailable)"
	}
	results := "masked (the agent's view)"
	if s.showResults {
		results = Paint.Yellow("shown here in clear, personal data included")
	}
	unmask := "refused (:unmask allows it)"
	if s.allowUnmask {
		unmask = Paint.Red("allowed: clients may ask for unmasked output, approved here each time")
	}
	pending := "none"
	if s.pending != nil {
		pending = Paint.Red("a loosening awaits :review")
	}
	rows := [][2]string{
		{"profile", fmt.Sprintf("%s · %s · production %t", st.Profile, sanitize.Terminal(s.profile.Where, false), st.Production)},
		{"mode", mode + Paint.Dim(" (Shift+Tab or :mode)")},
		{"results", results + Paint.Dim(" (Ctrl-O or :results)")},
		{"unmask", unmask + Paint.Dim(" (:unmask)")},
		{"session", fmt.Sprintf("ends in %d min (max_session %s) · idle_timeout %s", st.SessionEndsInS/60, s.profile.MaxSession, s.profile.IdleTimeout)},
		{"policy change", pending},
	}
	for _, l := range s.approved.Describe() {
		rows = append(rows, [2]string{"policy", sanitize.Terminal(l, false)})
	}
	if s.cfg.Boundary != "" {
		b := s.cfg.Boundary
		if !s.fingerprintLevel() {
			b = Paint.Red(b)
		}
		rows = append(rows, [2]string{"boundary", b})
	}
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
	parts := []string{name}
	mode := Paint.Green("manual")
	if s.autoApprove() {
		mode = Paint.Paint(bold+ui.Yellow, "AUTO")
	}
	if s.profile.Production {
		parts = append(parts, "mode "+mode)
	} else {
		parts = append(parts, "mode "+mode+" "+Paint.Dim("⇧Tab"))
	}
	results := Paint.Dim("masked")
	if s.showResults {
		results = Paint.Yellow("clear")
	}
	parts = append(parts, "results "+results+" "+Paint.Dim("^O"))
	if s.allowUnmask {
		parts = append(parts, Paint.Red("unmask allowed"))
	}
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
