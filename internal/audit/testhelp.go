package audit

// TamperForTest corrupts a stored record so Verify will fail. It exists only to
// let CLI-level tests exercise the failure path without reaching into SQL; it is
// not part of the public contract and must not be called in production.
func (l *SQLiteLogger) TamperForTest() error {
	_, err := l.db.Exec(`UPDATE audit_log SET detail = '{"tampered":true}' WHERE seq = 1`)
	return err
}
