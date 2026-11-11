package routes

// Listed reports whether name is in the table, whatever its treatment and
// ports. The names a table lists are a set the owner chose, so they may be
// told apart in metrics where a name the workspace made up may not.
func (t *Table) Listed(name string) bool {
	_, ok := t.destinations[Normalize(name)]
	return ok
}
