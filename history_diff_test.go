package main

import "testing"

const (
	testJobName = "test"
	testReadAll = "read-all"
)

func TestDiffSignalsIgnoresLineMoves(t *testing.T) {
	previous := signalMap(
		Signal{Check: checkTokenPermissions, Kind: permissionKindJobLevel, Name: testJobName, Value: testReadAll, Path: testWorkflowPath, Line: 4},
		Signal{Check: checkTokenPermissions, Kind: permissionKindJobLevel, Name: testJobName, Value: testReadAll, Path: testWorkflowPath, Line: 10},
	)
	current := signalMap(
		Signal{Check: checkTokenPermissions, Kind: permissionKindJobLevel, Name: testJobName, Value: testReadAll, Path: testWorkflowPath, Line: 6},
		Signal{Check: checkTokenPermissions, Kind: permissionKindJobLevel, Name: testJobName, Value: testReadAll, Path: testWorkflowPath, Line: 12},
	)

	if changes := diffSignals(previous, current); len(changes) != 0 {
		t.Fatalf("line moves produced changes: %#v", changes)
	}
}

func TestDiffSignalsKeepsDuplicateCountChanges(t *testing.T) {
	signal := Signal{
		Check: checkTokenPermissions,
		Kind:  permissionKindJobLevel,
		Name:  testJobName,
		Value: testReadAll,
		Path:  testWorkflowPath,
	}

	previous := signalMap(signalAtLine(signal, 10))
	current := signalMap(signalAtLine(signal, 1), signalAtLine(signal, 9))
	added := diffSignals(previous, current)
	if len(added) != 1 || added[0].Marker != '+' || added[0].Signal.Line != 1 {
		t.Fatalf("added duplicate changes = %#v", added)
	}

	removed := diffSignals(current, previous)
	if len(removed) != 1 || removed[0].Marker != '-' || removed[0].Signal.Line != 1 {
		t.Fatalf("removed duplicate changes = %#v", removed)
	}
}

func TestDiffSignalsMatchesMovedDuplicatesByNearestLine(t *testing.T) {
	signal := Signal{
		Check: checkTokenPermissions,
		Kind:  permissionKindJobLevel,
		Name:  testJobName,
		Value: testReadAll,
		Path:  testWorkflowPath,
	}

	previous := signalMap(signalAtLine(signal, 10))
	current := signalMap(signalAtLine(signal, 9), signalAtLine(signal, 20))
	added := diffSignals(previous, current)
	if len(added) != 1 || added[0].Marker != '+' || added[0].Signal.Line != 20 {
		t.Fatalf("added duplicate changes = %#v", added)
	}

	removed := diffSignals(current, previous)
	if len(removed) != 1 || removed[0].Marker != '-' || removed[0].Signal.Line != 20 {
		t.Fatalf("removed duplicate changes = %#v", removed)
	}
}

func TestDiffSignalsKeepsSemanticChangesAcrossLineMoves(t *testing.T) {
	previous := signalMap(Signal{
		Check: checkTokenPermissions,
		Kind:  permissionKindTopLevel,
		Value: "write-all",
		Path:  testWorkflowPath,
		Line:  2,
	})
	current := signalMap(Signal{
		Check: checkTokenPermissions,
		Kind:  permissionKindTopLevel,
		Value: testReadAll,
		Path:  testWorkflowPath,
		Line:  4,
	})

	changes := diffSignals(previous, current)
	if len(changes) != 2 || changes[0].Marker != '+' || changes[1].Marker != '-' {
		t.Fatalf("semantic changes = %#v", changes)
	}
}

func signalMap(signals ...Signal) map[string]Signal {
	result := make(map[string]Signal, len(signals))
	for _, signal := range signals {
		result[signalKey(signal)] = signal
	}
	return result
}

func signalAtLine(signal Signal, line uint) Signal {
	signal.Line = line
	return signal
}
