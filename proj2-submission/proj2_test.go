package proj2

import "github.com/nweaver/cs161-p2/userlib"
import "testing"
import "reflect"

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

	usr, err := InitUser("jonathan", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}

	// Check that fields of user are correctly initialized.
	if usr.Username == nil || usr.Password == nil || usr.Salt == nil {
		t.Error("Field empty when initializing User struct.", err)
		// } else if usr.PubKey == nil || usr.PrivKey == nil {
		// 	t.Error("Field empty when initializing User struct.", err)
	} else if usr.Shared == nil || usr.Created == nil {
		t.Error("Field empty when initializing User struct.", err)
	}

	// Check that alice was initialized correctly
	one, err := GetUser("jonathan", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to get user (call one)", err)
	}
	two, err := GetUser("jonathan", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to get user (call two)", err)
	}

	// Test storing with first call, loading with second
	// Also checks that files of same name can be stored
	one.StoreFile("test", []byte("testing123"))
	file, err := two.LoadFile("test")
	if string(file) != "testing123" {
		t.Error("LoadFile failed", err)
	}
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

func TestHMAC(t *testing.T) {
	msg := []byte("message")
	key := []byte("key")
	one := hmac(msg, key)
	two := hmac(msg, key)
	if !reflect.DeepEqual(one, two) {
		t.Error("Simple HMAC test failed.")
	}
}
func TestCryptoSimple(t *testing.T) {
	msg := []byte("message")
	// Make sure length is valid here
	key := []byte("strongkeyvalue12")
	efile := encrypt(key, msg)
	data := decrypt(key, efile)
	if !reflect.DeepEqual(msg, data) {
		t.Error("Simple encryption/decryption test failed.")
	}
}

func TestStoreAppendLoad(t *testing.T) {
	// Create user alice
	user, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", user)

	// Initialize testfile
	filename := "testfile"
	data := []byte("testing123")

	// Check StoreFile
	user.StoreFile(filename, data)

	// Check LoadFile
	load, err := user.LoadFile(filename)
	if err != nil {
		t.Error("Failed to upload and download", err)
	}
	if !reflect.DeepEqual(data, load) {
		t.Error("Downloaded file is not the same", data, load)
	}

	// Check AppendFile
	user.AppendFile(filename, data)
	load, err = user.LoadFile(filename)
	if err != nil {
		t.Error("Failed to reload data", err)
	}
	data = []byte("testing123testing123")
	if !reflect.DeepEqual(data, load) {
		t.Error("Downloaded file is not the same", data, load)
	}
}

func TestShareReceiveFile(t *testing.T) {
	// Create user alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	// Create user bob
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	// Create a file under alice's profile and store it
	filename := "alicefile"
	data := []byte("testing123")
	u.StoreFile(filename, data)

	// Load the file under alice's privileges
	loadalice, err := u.LoadFile(filename)
	if err != nil {
		t.Error("Failed to reload data", err)
	}
	if !reflect.DeepEqual(data, loadalice) {
		t.Error("Downloaded file is not the same", data, loadalice)
	}

	// Have alice share the file with bob
	msgid, err := u.ShareFile(filename, "bob")
	if err != nil {
		t.Error("Call to ShareFile failed", err)
	}

	// Have bob receive the file and check equal
	u2.ReceiveFile(filename, "alice", msgid)
	loadbob, err := u2.LoadFile(filename)
	if err != nil {
		t.Error("Failed receive shared file", err)
		return
	}
	if !reflect.DeepEqual(data, loadbob) {
		t.Error("Downloaded file is not the same", data, loadbob)
	}
}

func TestRevoke(t *testing.T) {
	// Create user alice
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}
	// Create user bob
	bob, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}

	// Create file under alice's permissions
	filename := "test"
	data := []byte("testing123")
	alice.StoreFile(filename, data)

	// Share the file with bob
	recipient := "bob"
	msgid, err := alice.ShareFile(filename, recipient)
	bob.ReceiveFile(filename, "alice", msgid)

	// Check that bob does not have ability to revoke file from alice
	err = bob.RevokeFile(filename)
	if err == nil {
		t.Error("File revoked by user other than creator.", err)
	}

	// Check that bob's call to RevokeFile did not remove alice's access
	_, err = alice.LoadFile(filename)
	if err != nil {
		t.Error("Call to RevokeFile by unauthorized user terminated creator's access!", err)
	}

	// Check that RevokeFile works
	err = alice.RevokeFile(filename)
	if err != nil {
		t.Error("RevokeFile failed under correct conditions.", err)
	}
	// Check that alice still has access to file
	_, err = alice.LoadFile(filename)
	if err != nil {
		t.Error("Call to RevokeFile by AUTHORIZED user terminated creator's access!", err)
	}
	// But bob does not
	err = bob.RevokeFile(filename)
	if err == nil {
		t.Error("RevokeFile did not revoke access to other users.", err)
	}
}
