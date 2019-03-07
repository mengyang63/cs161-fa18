package proj2

import "github.com/nweaver/cs161-p2/userlib"
import "testing"
import (
	"reflect"
	)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	someUsefulThings()

	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestAppend(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	msg := []byte("This is Msg. ")
	u.StoreFile("fileAppend", msg)

	// Append for the first time
	appendMsg1 := []byte("This is appendMsg 1. ")
	errAppend1 := u.AppendFile("fileAppend", appendMsg1)
	if errAppend1 != nil {
		t.Error("Failed to append message 1", errAppend1)
	}
	// Load for check
	loadMsg1, errLoad1 := u.LoadFile("fileAppend")
	if errLoad1 != nil {
		t.Error("Failed to upload and download 1", errLoad1)
	}
	// Check correctness
	newMsg1 := append(msg, appendMsg1...)
	if !reflect.DeepEqual(loadMsg1, newMsg1) {
		t.Error("Downloaded file is not the same 1", loadMsg1, newMsg1)
	}
	// Append for the second time
	appendMsg2 := []byte("This is appendMsg 2. ")
	errAppend2 := u.AppendFile("fileAppend", appendMsg2)
	if errAppend2 != nil {
		t.Error("Failed to append message 2", errAppend2)
	}
	// Load for check
	loadMsg2, errLoad2 := u.LoadFile("fileAppend")
	if errLoad2 != nil {
		t.Error("Failed to upload and download 2", errLoad2)
	}
	// Check correctness
	newMsg2 := append(newMsg1, appendMsg2...)
	if !reflect.DeepEqual(loadMsg2, newMsg2) {
		t.Error("Downloaded file is not the same 1", loadMsg2, newMsg2)
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}

	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}

	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
}

// Test overwrite

// Test revoke

// Other tests