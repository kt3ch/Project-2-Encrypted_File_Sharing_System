package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	 "strings"
	"testing"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestInitGet(t *testing.T) {
	//basic functionality tests for Init and GetUser
	clear()
	userlib.SetDebugStatus(true)
	datastore := userlib.DatastoreGetMap()
	//tests for unique username and multiple instances of a username
	alice, err := InitUser("alice", "soupcorn!")
	if alice == nil || err != nil {
		t.Error(err)
		return
	}
	getAlice1, err := GetUser("alice", "soupcorn!")
		if getAlice1 == nil || err != nil {
			t.Error(err)
			return
		}
	getAlice2, err := GetUser("alice", "soupcorn!")
		if getAlice2 == nil || err != nil {
			t.Error(err)
			return
		}
	_, err = InitUser("alice", "repeated")
	if err == nil {
		t.Error("Username is already taken")
		return
	}
	//tests for correct password
	_, err = GetUser("alice", "winter")
	if err ==  nil {
		t.Error("Password is incorrect")
		return
	}
	_, err = GetUser("bob", "soupcorn!")
	if err == nil {
		t.Error("Invalid login credentials")
		return
	}
	//tests for confidential username and password
	var keys []userlib.UUID
	var vals [][]byte
	for k, v := range datastore {
		keys = append(keys, k)
		vals = append(vals, v)
	}
	for val := range vals {
		if strings.Contains("alice", string(val)) || strings.Contains("soupcorn!", string(val)) {
			t.Error("Username or password is not obscured.")
			return
		}
	}
}

func TestGetUser(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Created user", u)
	t.Log("Start GetUser test")
	gu, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}
	t.Log("Get user", reflect.DeepEqual(u, gu))
}

func TestStorage(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a tetttttttst")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}
func TestUser_AppendFile(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := userlib.RandomBytes(10000)
	u.StoreFile("file1", v[:9000])

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v[:9000], v2) {
		t.Error("Downloaded file is not the same", v)
		return
	}
	err = u.AppendFile("file1", v[9000:])
	v3, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Downloaded Append file is not the same")
		return
	}

}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}
