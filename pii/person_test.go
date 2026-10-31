package pii

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"
)

// personTemplates are the positions a name takes in log lines and
// tickets. %s is the name.
var personTemplates = []string{
	"render pdf for %s failed: upstream timed out",
	"order 4812 placed by %s",
	`{"level":"info","msg":"invoice sent to %s","order_id":4812}`,
	"level=info msg=\"password reset requested by %s\" status=200",
	"2026-10-30T14:02:11Z INFO user %s logged in from the mobile app",
	"Oct 30 14:02:11 web1 shop[123]: refund approved for %s (ticket 991)",
	"Ticket #4471: %s reports the checkout page is blank",
	"Hello %s, your order has shipped.",
	"assigned to %s",
	"[2026-10-30 14:02:11] production.ERROR: payment declined for customer %s",
	"commit 68b724d by %s: fix rounding",
	"%s cancelled subscription 7781",
	"customer=\"%s\" plan=pro",
	"Delivery to %s rescheduled to Monday",
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// TestPersonNameRecall: every name of the corpus in every template; a
// name counts as found when no word of it is left in clear. The gate is
// the release target (PII-01): recall ≥ 90 %.
func TestPersonNameRecall(t *testing.T) {
	d := detector(t, "person_name")
	names := readLines(t, "testdata/person-names.txt")
	found, total := 0, 0
	var missed []string
	for _, n := range names {
		bare := n
		for _, h := range []string{"Mr. ", "Mrs ", "Mme ", "M. ", "Dr. ", "Prof. ", "Herr ", "Frau ", "Sra. ", "Dhr. "} {
			bare = strings.TrimPrefix(bare, h)
		}
		for _, tpl := range personTemplates {
			total++
			in := fmt.Sprintf(tpl, n)
			out := d.Mask(in)
			leak := false
			for _, w := range strings.FieldsFunc(bare, func(r rune) bool { return r == ' ' || r == '.' }) {
				if len(w) >= 2 && strings.Contains(out, w) && !strings.Contains(fmt.Sprintf(tpl, ""), w) {
					leak = true
				}
			}
			if leak {
				missed = append(missed, in+" => "+out)
			} else {
				found++
			}
		}
	}
	recall := float64(found) / float64(total)
	t.Logf("person_name recall: %.1f %% (%d/%d over %d names × %d templates)", 100*recall, found, total, len(names), len(personTemplates))
	if recall < 0.90 {
		for _, m := range missed[:min(len(missed), 40)] {
			t.Log("missed:", m)
		}
		t.Errorf("recall %.3f < 0.90", recall)
	}
}

// TestPersonNameHeldOutRecall reports recall on names whose given names
// the gazetteer was not tuned for: an honest number, not a gate.
func TestPersonNameHeldOutRecall(t *testing.T) {
	d := detector(t, "person_name")
	names := readLines(t, "testdata/person-names-heldout.txt")
	found := 0
	for _, n := range names {
		in := "refund approved for " + n + " (ticket 991)"
		out := d.Mask(in)
		leak := false
		for _, w := range strings.Fields(n) {
			if strings.Contains(out, w) {
				leak = true
			}
		}
		if !leak {
			found++
		}
	}
	recall := float64(found) / float64(len(names))
	t.Logf("person_name held-out recall: %.1f %% (%d/%d)", 100*recall, found, len(names))
	// Report only: names outside the gazetteer are found only after a
	// title (GUIDE §8), so this number is low by design.
	_ = recall
}

// Words, products and abbreviations reviewers found masked: never names.
func TestPersonNameKeepsWords(t *testing.T) {
	d := detector(t, "person_name")
	for _, in := range []string{
		"MS Teams crashed", "MX Lookup failed", "MR Approved by bot", "MR Merged into main",
		"DR Failover completed", "SR Ticket 4471", "Sr Developer role", "Sr. Software Engineer opening",
		"L2 Cache Miss Ratio", "max_price=100", "MAX_PRICE=100", "order.bill.price=12", "mark_hall=1",
		"rate=max_wood", "Max Price: 120 EUR", "MAX PRICE EXCEEDED", "Felix ServiceRegistry",
		"gpgv: Signature made Thu Apr 23 10:00:00 2026 UTC", "Date:   Thu Oct 23 10:00:00 2026 +0200",
		"Thu Oct 29 14:02:11 CET 2026", "Can Reach Host? false", "Lan Interface eth0 up",
		"Nand Flash ECC error at block 12", "Mai Juni 2026",
		"Hugo Theme", "Started Hugo Static Site.", "Cassandra Keyspace", "Bruno Collection",
		"Leon Fixture", "Adam Optimizer", "Tim Sort", "Kelly Criterion", "Simon Says",
		"Milan Cathedral", "Oscar Nominee", "Charlotte Hornets", "Morgan Stanley",
		"Stella Artois", "Kevin Workflow", "the customer said black screen", "per de week",
	} {
		if got := d.Mask(in); got != in {
			t.Errorf("person_name.Mask(%q) = %q, want unchanged", in, got)
		}
	}
	for in, gone := range map[string]string{"Lars Løkke Rasmussen said": "Rasmussen", "ticket for Mike Kowalczyk": "Kowalczyk"} {
		if got := d.Mask(in); strings.Contains(got, gone) {
			t.Errorf("person_name.Mask(%q) = %q, keeps %q", in, got, gone)
		}
	}
	for _, in := range []string{"Kevin VANDEPUTTE called", "J. Smith called", "Jean\tDupont called", "MR SMITH called", "Ms Smith called"} {
		if got := d.Mask(in); got == in {
			t.Errorf("person_name.Mask(%q) unchanged, want the name masked", in)
		}
	}
}

// TestPersonNameHeldOutFalsePositives: held-out tickets, release notes,
// systemd and Kubernetes lines with no real person's name; at most 5 %
// hit (prose in title case is harder than log lines). "Linus Torvalds"
// and "Harry Potter" are people, real or fictional: masking them is right.
func TestPersonNameHeldOutFalsePositives(t *testing.T) {
	d := detector(t, "person_name")
	lines := readLines(t, "testdata/person-fp-heldout.txt")
	fp := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "Linus Torvalds") || strings.HasPrefix(l, "Harry Potter") {
			continue
		}
		if got := d.Mask(l); got != l {
			fp++
			t.Logf("fp: %s => %s", l, got)
		}
	}
	rate := float64(fp) / float64(len(lines))
	t.Logf("person_name held-out false positives: %.1f %% (%d/%d)", 100*rate, fp, len(lines))
	if rate > 0.05 {
		t.Errorf("held-out false-positive rate %.3f > 0.05", rate)
	}
}

// loghubStyle generates log lines in the shapes of the Loghub datasets
// (HDFS, Hadoop, Spark, Zookeeper, BGL, HPC, Thunderbird, Windows, Linux,
// Android, Apache, OpenSSH, OpenStack, Mac, Proxifier), seeded.
func loghubStyle(n int) []string {
	r := rand.New(rand.NewSource(26))
	pick := func(xs ...string) string { return xs[r.Intn(len(xs))] }
	num := func(k int) string { return fmt.Sprint(r.Intn(k)) }
	ip := func() string { return "10." + num(255) + "." + num(255) + "." + num(255) }
	blk := func() string { return "blk_" + fmt.Sprint(r.Int63()) }
	gen := []func() string{
		func() string {
			return "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder " + num(3) + " for block " + blk() + " terminating"
		},
		func() string {
			return "081109 204005 35 INFO dfs.FSNamesystem: BLOCK* NameSystem.addStoredBlock: blockMap updated: " + ip() + ":50010 is added to " + blk() + " size " + num(67108864)
		},
		func() string {
			return "081111 101621 2601 WARN dfs.DataNode$DataXceiver: " + ip() + ":50010:Got exception while serving " + blk() + " to /" + ip() + ":"
		},
		func() string {
			return "2015-10-18 18:01:47,978 INFO [main] org.apache.hadoop.mapreduce.v2.app.MRAppMaster: Created MRAppMaster for application appattempt_1445144423722_0020_000001"
		},
		func() string {
			return "17/06/09 20:10:40 INFO executor.CoarseGrainedExecutorBackend: Registered signal handlers for [TERM, HUP, INT]"
		},
		func() string {
			return "17/06/09 20:10:41 INFO spark.SecurityManager: Changing view acls to: yarn,curi"
		},
		func() string {
			return "17/06/09 20:11:11 INFO storage.BlockManager: Found block rdd_" + num(99) + "_" + num(9) + " locally"
		},
		func() string {
			return "2015-07-29 17:41:44,747 - INFO  [QuorumPeer[myid=1]/0:0:0:0:0:0:0:0:2181:FastLeaderElection@774] - Notification time out: " + num(60000)
		},
		func() string {
			return "2015-07-29 19:04:12,394 - WARN  [RecvWorker:188978561024:QuorumCnxManager$RecvWorker@762] - Connection broken for id 188978561024, my id = 1, error ="
		},
		func() string {
			return "- 1117838570 2005.06.03 R02-M1-N0-C:J12-U11 2005-06-03-15.42.50.675872 R02-M1-N0-C:J12-U11 RAS KERNEL INFO instruction cache parity error corrected"
		},
		func() string {
			return "- 1131566461 2005.11.09 tbird-admin1 Nov 10 00:01:01 local@tbird-admin1 postfix/postdrop[10896]: warning: unable to look up public/pickup: No such file or directory"
		},
		func() string {
			return "2016-09-28 04:30:30, Info                  CBS    Loaded Servicing Stack v6.1.7601.23505 with Core: C:\\Windows\\winsxs\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_6.1.7601.23505_none_681aa442f6fed7f0\\cbscore.dll"
		},
		func() string {
			return "2016-09-28 04:30:31, Info                  CSI    00000001@2016/9/27:20:30:31.455 WcpInitialize (wcp.dll version 0.0.0.6) called (stack @0x7fed806eb5d @0x7fef9fb9b6d)"
		},
		func() string {
			return "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=" + ip()
		},
		func() string {
			return "Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)"
		},
		func() string {
			return "Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: IOThunderboltSwitch<0>(0x0)::listenerCallback - Thunderbolt HPD packet for route = 0x0 port = 11 unplug = 0"
		},
		func() string {
			return "03-17 16:13:38.811  1702  2395 D WindowManager: printFreezingDisplayLogsopening app wtoken = AppWindowToken{9f4ef63 token=Token{a64f992 ActivityRecord{de9231d u0 com.tencent.qt.qtl/.activity.info.NewsDetailXmlActivity t761}}}, allDrawn= false"
		},
		func() string {
			return "[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties"
		},
		func() string {
			return "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state " + num(9)
		},
		func() string {
			return "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from " + ip()
		},
		func() string {
			return "Dec 10 07:07:38 LabSZ sshd[24206]: Failed password for invalid user test9 from " + ip() + " port " + num(65535) + " ssh2"
		},
		func() string {
			return "Dec 10 09:12:32 LabSZ sshd[24490]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=" + ip() + "  user=root"
		},
		func() string {
			return "nova-api.log.1.2017-05-16_13:53:08 2017-05-16 00:00:00.008 25746 INFO nova.osapi_compute.wsgi.server [req-38101a0b-2096-447d-96ea-a692162415ae 113d3a99c3da401fbd62cc2caa5b96d2 54fadb412c4e40cdbaed9335e4c35a9e - - -] " + ip() + " \"GET /v2/54fadb412c4e40cdbaed9335e4c35a9e/servers/detail HTTP/1.1\" status: 200 len: 1893 time: 0.2477829"
		},
		func() string {
			return "[10.30 16:49:06] chrome.exe - proxy.cse.cuhk.edu.hk:5070 open through proxy proxy.cse.cuhk.edu.hk:5070 HTTPS"
		},
		func() string {
			return pick("Started", "Stopped", "Reloaded", "Starting") + " " + pick("Session", "User Manager", "Daily apt upgrade", "Network Manager", "Docker Application Container Engine") + " " + num(999) + "."
		},
		func() string {
			return "Mark Done: task " + num(999) + " in " + pick("Kevin Pipeline", "Max Pool", "Grant Access", "Will Retry") + " stage"
		},
		func() string {
			return pick("Jordan", "Austin", "Florence", "Victoria", "Paris", "Chelsea") + " " + pick("Region", "Datacenter", "Office", "Station", "Cluster") + " health check ok"
		},
	}
	out := make([]string, n)
	for i := range out {
		out[i] = gen[r.Intn(len(gen))]()
	}
	return out
}

// TestPersonNameFalsePositives: on 2 000 Loghub-style lines, at most 1 %
// of the lines lose a word to person_name (PII-04).
func TestPersonNameFalsePositives(t *testing.T) {
	d := detector(t, "person_name")
	lines := loghubStyle(2000)
	fp := 0
	var hits []string
	for _, l := range lines {
		if got := d.Mask(l); got != l {
			fp++
			if len(hits) < 20 {
				hits = append(hits, l+" => "+got)
			}
		}
	}
	rate := float64(fp) / float64(len(lines))
	t.Logf("person_name false positives: %.2f %% of %d Loghub-style lines", 100*rate, len(lines))
	if rate > 0.01 {
		for _, h := range hits {
			t.Log("fp:", h)
		}
		t.Errorf("false-positive rate %.4f > 0.01", rate)
	}
}

func TestPersonNameCases(t *testing.T) {
	d := detector(t, "person_name")
	for in, want := range map[string]string{
		"sent to Jean Dupont today":         "sent to J***(11) today",
		"Ludwig van Beethoven wrote":        "L***(20) wrote",
		"call Mr. Smith now":                "call Mr. S***(5) now",
		"M. Dupont a appelé":                "M. D***(6) a appelé",
		"by john.smith on main":             "by j***(10) on main",
		"Will Smith joined":                 "W***(10) joined",
		"Will retry in 5 s":                 "Will retry in 5 s",
		"Max Connections reached":           "Max Connections reached",
		"Mark Done":                         "Mark Done",
		"Jan 30 14:02:11 web1 kernel":       "Jan 30 14:02:11 web1 kernel",
		"Daniel Started the job":            "Daniel Started the job",
		"Thomas":                            "Thomas",
		"Smith":                             "Smith",
		"M Dupont":                          "M Dupont",
		"John F. Kennedy":                   "J***(15)",
		"Jean-Pierre Lefèvre":               "J***(19)",
		"O'Brien said Sinead O'Connor left": "O'Brien said S***(15) left",
	} {
		if got := d.Mask(in); got != want {
			t.Errorf("person_name.Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPersonNameLinear(t *testing.T) {
	d := detector(t, "person_name")
	for name, in := range map[string]string{
		"names":  strings.Repeat("John ", DetectLimit/5),
		"titles": strings.Repeat("Mr. ", DetectLimit/4),
		"long":   strings.Repeat("a", DetectLimit),
		"marks":  strings.Repeat("e\u0301", DetectLimit/3),
	} {
		start := time.Now()
		d.Mask(in)
		if el := time.Since(start); el > 500*time.Millisecond {
			t.Errorf("%s: %v", name, el)
		}
	}
}

func FuzzPersonNameNoPanic(f *testing.F) {
	for _, s := range []string{"Jean Dupont", "Mr. ", "M.", "john.smith", "Ludwig van", "O'", "Jean-"} {
		f.Add(s)
	}
	d, _ := Detectors([]string{"person_name"})
	f.Fuzz(func(t *testing.T, s string) {
		out := d[0].Mask(s)
		if strings.Contains(s, "Jean Dupont") && strings.Contains(out, "Jean Dupont") && !strings.ContainsAny(s, "_.") {
			// Known given name + known surname, blank-separated: always
			// masked unless glued into a longer word.
			i := strings.Index(s, "Jean Dupont")
			if !gluedLetter(s, i-1) && !gluedLetter(s, i+len("Jean Dupont")) {
				t.Errorf("Mask(%q) = %q keeps Jean Dupont", s, out)
			}
		}
	})
}

// gluedLetter reports a byte at s[i] that would glue a name to a longer
// word (anything but a blank, a newline or the edges of s).
func gluedLetter(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	return s[i] != ' ' && s[i] != '\n' && s[i] != '\t'
}
