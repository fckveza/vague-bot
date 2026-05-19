package vaguebot

import "testing"

func TestFirstNonEmpty(t *testing.T) {
	got := firstNonEmpty("", "  ", "value", "other")
	if got != "value" {
		t.Fatalf("firstNonEmpty() = %q, want %q", got, "value")
	}
}

func TestMessageTypeFromTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		group  bool
	}{
		{name: "private cid", target: "w123", group: false},
		{name: "group g prefix", target: "g123", group: true},
		{name: "group c prefix", target: "c123", group: true},
		{name: "group r prefix", target: "r123", group: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := messageTypeFromTarget(test.target)
			if test.group && got != 1 {
				t.Fatalf("messageTypeFromTarget(%q) = %v, want group", test.target, got)
			}
			if !test.group && got != 0 {
				t.Fatalf("messageTypeFromTarget(%q) = %v, want private", test.target, got)
			}
		})
	}
}
