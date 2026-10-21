package abuse

import "testing"

func TestStats_CountsTriggeredAndPerBackendDispatches(t *testing.T) {
	a, b := newFake("A"), newFake("B")
	m := stoppable(t, newTestManager(2, a, b))

	if st := m.Stats(); st.ReportsTriggered != 0 || st.ReportsSent != 0 {
		t.Fatalf("fresh manager stats = %+v, want zeros", st)
	}

	m.RecordFailure("198.51.100.1", "SSH", "root", "x") // below threshold
	if st := m.Stats(); st.ReportsTriggered != 0 {
		t.Fatalf("triggered below threshold: %+v", st)
	}
	if !m.RecordFailure("198.51.100.1", "SSH", "root", "y") {
		t.Fatal("expected report on second attempt")
	}
	a.next(t)
	b.next(t)

	m.RecordFailure("198.51.100.2", "Telnet", "admin", "x")
	m.RecordFailure("198.51.100.2", "Telnet", "admin", "y")
	a.next(t)
	b.next(t)

	st := m.Stats()
	if st.ReportsTriggered != 2 {
		t.Errorf("ReportsTriggered = %d, want 2", st.ReportsTriggered)
	}
	if st.ReportsSent != 4 {
		t.Errorf("ReportsSent = %d, want 4 (2 reports x 2 backends)", st.ReportsSent)
	}
	if st.SentByBackend["A"] != 2 || st.SentByBackend["B"] != 2 {
		t.Errorf("SentByBackend = %v, want A:2 B:2", st.SentByBackend)
	}
}

func TestStats_NilManagerAndNoBackends(t *testing.T) {
	var nilM *Manager
	if st := nilM.Stats(); st.ReportsSent != 0 || st.SentByBackend == nil {
		t.Errorf("nil manager stats = %+v", st)
	}
	m := stoppable(t, newTestManager(1))
	m.RecordFailure("198.51.100.3", "SSH", "root", "x")
	if st := m.Stats(); st.ReportsSent != 0 || st.ReportsTriggered != 0 {
		t.Errorf("no-backend stats = %+v, want zeros", st)
	}
}
