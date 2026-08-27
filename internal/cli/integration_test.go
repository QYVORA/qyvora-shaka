package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "shaka-cli-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	binPath = filepath.Join(dir, "shaka")
	cmd := exec.Command("go", "build", "-o", binPath, "github.com/QYVORA/qyvora-shaka/cmd/shaka")
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic("building shaka binary: " + err.Error() + ": " + string(out))
	}
	os.Exit(m.Run())
}

// runShaka executes the shaka binary in an isolated working directory and
// returns its exit code and standard output.
func runShaka(t *testing.T, stdin ioReader, args ...string) (int, string) {
	t.Helper()
	work, err := os.MkdirTemp("", "shaka-cli-work")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	defer os.RemoveAll(work)

	c := exec.Command(binPath, args...)
	c.Dir = work
	if stdin != nil {
		c.Stdin = stdin
	}
	out, err := c.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("exec %v: %v", args, err)
	}
	return code, string(out)
}

func TestAssessSimWritesSessionAndExitsZero(t *testing.T) {
	code, out := runShaka(t, nil, "assess", "--sim")
	if code != 0 {
		t.Fatalf("assess --sim exit = %d, want 0; out:\n%s", code, out)
	}
	work, err := os.MkdirTemp("", "shaka-cli-sess")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(work)
	c := exec.Command(binPath, "assess", "--sim")
	c.Dir = work
	if out2, err := c.CombinedOutput(); err != nil {
		t.Fatalf("assess --sim: %v: %s", err, out2)
	}
	matches, _ := filepath.Glob(filepath.Join(work, "sessions", "*.session.json"))
	if len(matches) == 0 {
		t.Fatalf("expected a persisted session file")
	}
}

func TestAuthGateDeclinesLiveTargetExitsOne(t *testing.T) {
	code, out := runShaka(t, nil, "assess", "--endpoint", "ldap://127.0.0.1:9")
	if code != 1 {
		t.Fatalf("auth-gate decline exit = %d, want 1; out:\n%s", code, out)
	}
}

func TestUnknownCommandExitsUsage(t *testing.T) {
	code, _ := runShaka(t, nil, "no-such-command")
	if code != 2 {
		t.Fatalf("unknown command exit = %d, want 2", code)
	}
}

func TestVersionExitsZero(t *testing.T) {
	code, out := runShaka(t, nil, "version")
	if code != 0 {
		t.Fatalf("version exit = %d, want 0; out:\n%s", code, out)
	}
}

type ioReader = interface{ Read([]byte) (int, error) }
