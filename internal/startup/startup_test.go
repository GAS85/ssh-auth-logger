package startup

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestGetEnvWithDefault(t *testing.T) {
	t.Setenv("STARTUP_TEST_SET", "value")
	t.Setenv("STARTUP_TEST_EMPTY", "")

	cases := map[string]string{
		"STARTUP_TEST_SET":     "value",
		"STARTUP_TEST_EMPTY":   "fallback", // blank counts as missing
		"STARTUP_TEST_MISSING": "fallback",
	}
	for key, want := range cases {
		if got := GetEnvWithDefault(key, "fallback"); got != want {
			t.Errorf("GetEnvWithDefault(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestAddIfNotDefault_Int(t *testing.T) {
	f := logrus.Fields{}
	AddIfNotDefault(f, "same", 3072, 3072)
	AddIfNotDefault(f, "diff", 4096, 3072)
	if _, ok := f["same"]; ok {
		t.Error("a value equal to the default must not be added")
	}
	if f["diff"] != 4096 {
		t.Errorf("diff = %v, want 4096", f["diff"])
	}
}

func TestAddIfNotDefault_String(t *testing.T) {
	f := logrus.Fields{}
	AddIfNotDefault(f, "same", "host", "host")
	AddIfNotDefault(f, "diff", "remote_ip", "host")
	AddIfNotDefault(f, "empty", "", "")
	AddIfNotDefault(f, "emptyVsDefault", "", "x") // explicitly emptied: differs from the default
	if _, ok := f["same"]; ok {
		t.Error("equal string added")
	}
	if _, ok := f["empty"]; ok {
		t.Error("empty value with empty default added")
	}
	if f["diff"] != "remote_ip" {
		t.Errorf("diff = %v", f["diff"])
	}
	if v, ok := f["emptyVsDefault"]; !ok || v != "" {
		t.Errorf("an empty value differing from the default must be shown: %v", f)
	}
}

func TestAddIfNotDefault_Bool(t *testing.T) {
	f := logrus.Fields{}
	AddIfNotDefault(f, "stays", false, false)
	AddIfNotDefault(f, "changedToTrue", true, false)
	AddIfNotDefault(f, "changedToFalse", false, true)
	if _, ok := f["stays"]; ok {
		t.Error("default bool added")
	}
	if f["changedToTrue"] != true {
		t.Error("true != default false must be shown")
	}
	if v, ok := f["changedToFalse"]; !ok || v != false {
		t.Error("false != default true must be shown, as false")
	}
}

func TestAddIfNotDefault_KeepsExistingFields(t *testing.T) {
	f := logrus.Fields{"always": 1}
	AddIfNotDefault(f, "same", 1, 1)
	AddIfNotDefault(f, "diff", 2, 1)
	if len(f) != 2 || f["always"] != 1 || f["diff"] != 2 {
		t.Errorf("fields = %v", f)
	}
}

func TestAddIfNotDefault_DebugLevelShowsEverything(t *testing.T) {
	std := logrus.StandardLogger()
	old := std.GetLevel()
	t.Cleanup(func() { std.SetLevel(old) })

	for level, wantAll := range map[logrus.Level]bool{
		logrus.InfoLevel:  false,
		logrus.DebugLevel: true,
		logrus.TraceLevel: true,
	} {
		std.SetLevel(level)
		f := logrus.Fields{}
		AddIfNotDefault(f, "same", 1, 1)
		AddIfNotDefault(f, "diff", 2, 1)
		if _, shown := f["same"]; shown != wantAll {
			t.Errorf("level %v: default value shown = %v, want %v", level, shown, wantAll)
		}
		if f["diff"] != 2 {
			t.Errorf("level %v: non-default value must always be shown: %v", level, f)
		}
		if ShowAll() != wantAll {
			t.Errorf("level %v: ShowAll() = %v, want %v", level, ShowAll(), wantAll)
		}
	}
}
