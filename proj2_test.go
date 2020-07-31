package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_"encoding/json"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	"strings"
	"testing"
	_ "time"
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
func TestInitAndGetPt1(t *testing.T) {
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
	if err == nil {
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
	userlib.SetDebugStatus(true)
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
	magic_string1, err1 := u.ShareFile("file1", "bob")
	_ = magic_string1
	if err1 != nil {
		t.Error("This should be undefined behavior", err)
		return
	}
	userlib.DebugMsg("Magic string: %d", len(magic_string))
	if err != nil {
		t.Error("Failed to share the file", err)
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

// More comprehensive test on Init and GetUser
func TestInitAndGetPt2 (t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()

	_, err := InitUser("elise", "chips")
	if err != nil {
		t.Error(err)
		return
	}

	//check that a user cannot be fetched after Datastore clears
	userlib.DatastoreClear()
	_, err = GetUser("elise", "chips")
	if err == nil {
		t.Error("Datastore is empty but was still able to fetch user information")
	}

	clear()

	//checks for corruption after modifying datastore key-value pairs after InitUser
	keystore := userlib.KeystoreGetMap()
	datastore := userlib.DatastoreGetMap()

	_, _ = datastore, keystore

	_, err = InitUser("elise", "chips")
	if err != nil {
		t.Error(err)
		return
	}

	_, err = InitUser("ben", "chips")
	if err != nil {
		t.Error(err)
		return
	}

	var key []userlib.UUID
	var value [][]byte
	for k, v := range datastore {
		key = append(key, k)
		value = append(value, v)
	}

	for i := 1; i < len(key); i++ {
		userlib.DatastoreSet(key[i], value[0])
	}

	_, err = GetUser("elise", "chips")
	if err == nil {
		t.Error("Got user after attacker modified Elise's account information.")
		return
	}
	_, err = GetUser("ben", "chips")
	if err == nil {
		t.Error("Got user after attacker modified Ben's account information.")
		return
	}
}

func TestStoreAndShare(t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()

	elise, err := InitUser("elise", "chips")
	if err != nil {
		t.Error("Could not initialize Elise")
		return
	}
	ben, err := InitUser("ben", "chips")
	if err != nil {
		t.Error("Could not initialize Elise")
		return
	}
	jay, err := InitUser("jay", "okinawa")
	if err != nil {
		t.Error("Could not initialize Jay")
		return
	}
	randomContent := []byte("zzzzzzzzzz")
	elise.StoreFile("fileA", randomContent)
	eLoadFileA, err := elise.LoadFile("fileA")
	_ = eLoadFileA
	if err != nil {
		t.Error("Elise should be able to load this file")
		return
	}
	bLoadFileA, benLoadErr := ben.LoadFile("fileA")
	_ = bLoadFileA
	if benLoadErr == nil {
		t.Error("Ben should not be able to load this file")
		return
	}
	accessToken, err := elise.ShareFile("fileA", "ben")
	err = ben.ReceiveFile("renamedFileA", "elise", accessToken)
	if err != nil {
		t.Error("Ben should be able to receive this shared file")
		return
	}
	jayErr := jay.ReceiveFile("renamedFileA", "elise", accessToken)
	if jayErr == nil {
		t.Error("Jay should not be able to receive this shared file")
		return
	}
	bLoadFileA, benLoadErr = ben.LoadFile("renamedFileA")
	if benLoadErr != nil {
		t.Error("Ben should be able to load this file now")
		return
	}
	jLoadFileA, jayLoadErr := jay.LoadFile("renamedFileA")
	_ = jLoadFileA
	if jayLoadErr == nil {
		t.Error("Jay should not be able to load this file")
		return
	}
	if !reflect.DeepEqual(randomContent, bLoadFileA) {
		t.Error("The shared files are not equal")
		return
	}
	err = elise.RevokeFile("fileA", "ben")
	if err != nil {
		t.Error("Unable to revoke file access")
		return
	}
	bLoadFileA, benLoadErr = ben.LoadFile("renamedFileA")
	if benLoadErr == nil {
		t.Error("Ben should not be able to load this revoked file")
		return
	}
	moreRandomContent := []byte("additional info")
	err = elise.AppendFile("fileA", moreRandomContent)
	if err != nil {
		t.Error("Unable to append to file")
		return
	}
	eEditedLoadFile, lastErr := elise.LoadFile("fileA")
	_ = eEditedLoadFile
	if lastErr != nil {
		t.Error("Unable to load edited file")
		return
	}
	bEditedLoadFile, lastErr1 := ben.LoadFile("renamedFileA")
	_ = bEditedLoadFile
	if lastErr1 == nil {
		t.Error("Revoked file: Ben should not be able to load edited file")
		return
	}
}
func TestAppendAfterCorruption(t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore
	elise, eliseErr := InitUser("elise", "chips")
	if eliseErr != nil {
		t.Error("Failed to initilize Elise")
		return
	}
	randomContent := []byte("zzzzzzzzzz")
	elise.StoreFile("fileA", randomContent)
	eLoadFileA, loadErr := elise.LoadFile("fileA")
	_ = eLoadFileA
	if loadErr != nil {
		t.Error("Elise should be able to load this file")
		return
	}
	var key []userlib.UUID
	var value [][]byte
	for k, v := range datastore {
		key = append(key, k)
		value = append(value, v)
	}
	for i := 0; i < len(key); i++ {
		userlib.DatastoreSet(key[i], value[0])
	}
	appendInfo := []byte("uc berkeley class of 2021")
	err := elise.AppendFile("fileA", appendInfo)
	if err == nil {
		t.Error("File was corrupt but Elise was still able to append")
		return
	}
}

func TestCorruptAccessToken(t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore
	elise, eliseErr := InitUser("elise", "chips")
	if eliseErr != nil {
		t.Error("Failed to initilize Elise")
		return
	}
	ben, benErr := InitUser("ben", "chips")
	if benErr != nil {
		t.Error("Failed to initilize Ben")
		return
	}
	randomStuff := []byte("cake or icecream")
	elise.StoreFile("file1", randomStuff)
	eLoadFileA, err := elise.LoadFile("file1")
	_ = eLoadFileA
	if err != nil {
		t.Error("Elise should be able to load this file")
		return
	}
	magicNumber, magicErr := elise.ShareFile("file1", "ben")
	if magicErr != nil {
		t.Error("Failed to share this file")
		return
	}
	//modify magicNumber by one value
	modifiedMagicNum := magicNumber[:(len(magicNumber)-1)] + "a"
	recErr := ben.ReceiveFile("file1", "elise", modifiedMagicNum)
	if recErr == nil {
		t.Error("Received a corrupt file with incorrect access token")
		return
	}
	//input empty string as access token
	emptyToken := ""
	recErr1 := ben.ReceiveFile("eliseShared", "elise", emptyToken)
	if recErr1 == nil {
		t.Error("Received a corrupt file with incorrect access token")
		return
	}
	//input random access token
	randomAccessTokenBytes := userlib.RandomBytes(len(magicNumber))
	randomAccessToken := string(randomAccessTokenBytes)
	recErr2 := ben.ReceiveFile("eliseShared", "elise", randomAccessToken)
	if recErr2 == nil {
		t.Error("Received a corrupt file with incorrect access token")
		return
	}
}

func TestTypoInShare(t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore
	elise, eliseErr := InitUser("elise", "chips")
	if eliseErr != nil {
		t.Error("Failed to initilize Elise")
		return
	}
	ben, benErr := InitUser("ben", "chips")
	if benErr != nil {
		t.Error("Failed to initilize Ben")
		return
	}
	info := []byte("cs161.org")
	elise.StoreFile("file1", info)
	eLoadFileA, err := elise.LoadFile("file1")
	_ = eLoadFileA
	if err != nil {
		t.Error("Elise should be able to load this file")
		return
	}
	magicString, err := elise.ShareFile("file1", "ben")
	//typo test #1 -- access token
	err0 := ben.ReceiveFile("renamedFile1", "elise", "magicStringT")
	if err0 == nil {
		t.Error("Typo error")
		return
	}
	//typo test #1 -- sender
	err1 := ben.ReceiveFile("renamedFile1", "el0ise", magicString)
	if err1 == nil {
		t.Error("Typo error")
		return
	}
	//typo test #1 -- recipient
	magicString1, err2 := elise.ShareFile("file1", "bennnnnnn")
	_ = magicString1
	if err2 == nil {
		t.Error("Typo error")
		return
	}
}

func TestEdgeCases(t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore
	elise, eliseErr := InitUser("elise", "chips")
	if eliseErr != nil {
		t.Error("Failed to initilize Elise")
		return
	}
	ben, benErr := InitUser("ben", "chips")
	if benErr != nil {
		t.Error("Failed to initilize Ben")
		return
	}
	jay, jayErr := InitUser("jay", "chips")
	_ = jay
	if jayErr != nil {
		t.Error("Failed to initilize Jay")
		return
	}
	romeo := []byte("O Romeo, Romeo, wherefore art thou Romeo?")
	elise.StoreFile("file1", romeo)
	eLoadFileA, err := elise.LoadFile("file1")
	_ = eLoadFileA
	if err != nil {
		t.Error("Elise should be able to load this file")
		return
	}
	magicString, err := elise.ShareFile("file1", "ben")
	if err != nil {
		t.Error("Sharing error")
		return
	}
	err0 := ben.ReceiveFile("renamedFile1", "elise", magicString)
	if err0 != nil {
		t.Error("Ben should be able to receive this file")
		return
	}
	magicString1, err1 := ben.ShareFile("renamedFile1", "ben")
	_ = magicString1
	if err1 != nil {
		t.Error("This should be undefined behavior")
		return
	}
	magicString2, err2 := ben.ShareFile("renamedFile1", "jay")
	_ = magicString2
	if err2 != nil {
		t.Error("Sharing error")
		return
	}
	err3 := jay.ReceiveFile("renamedFile1", "elise", magicString2)
	if err3 == nil {
		t.Error("Wrong sender")
		return
	}
	err4 := jay.ReceiveFile("file1", "elise", magicString)
	if err4 == nil {
		t.Error("Wrong sender")
		return
	}
	err5 := jay.ReceiveFile("fromBen", "ben", magicString2)
	if err5 != nil {
		t.Error("Jay should be able to receive this file")
		return
	}
	//append tests
	extraStuff := []byte("Human beings can be very odd sometimes.")
	updatedFile := append(romeo, extraStuff...)
	err = elise.AppendFile("file1", extraStuff)
	if err != nil {
		t.Error("Append error")
		return
	}
	updatedLoad, loadErr := elise.LoadFile("file1")
	if !reflect.DeepEqual(updatedLoad, updatedFile) || loadErr != nil {
		t.Error("Files not updated")
		return
	}
	updatedLoad1, loadErr1 := ben.LoadFile("renamedFile1")
	if !reflect.DeepEqual(updatedLoad1, updatedFile) || loadErr1 != nil {
		t.Error("Files not updated")
		return
	}
	// updatedLoad2, loadErr2 := jay.LoadFile("fromBen")
	// if !reflect.DeepEqual(updatedLoad2, updatedFile) || loadErr2 != nil {
	// 	t.Error("Files not updated")
	// 	return
	// }
}
func TestEdgeCasesRevoke(t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()
	datastore := userlib.DatastoreGetMap()
	keystore := userlib.KeystoreGetMap()
	_, _ = datastore, keystore
	elise, eliseErr := InitUser("elise", "chips")
	if eliseErr != nil {
		t.Error("Failed to initilize Elise")
		return
	}
	ben, benErr := InitUser("ben", "chips")
	if benErr != nil {
		t.Error("Failed to initilize Ben")
		return
	}
	jay, jayErr := InitUser("jay", "chips")
	_ = jay
	if jayErr != nil {
		t.Error("Failed to initilize Jay")
		return
	}
	romeo := []byte("O Romeo, Romeo, wherefore art thou Romeo?")
	elise.StoreFile("file1", romeo)
	eLoadFileA, err := elise.LoadFile("file1")
	_ = eLoadFileA
	if err != nil {
		t.Error("Elise should be able to load this file")
		return
	}
	magicString, err := elise.ShareFile("file1", "ben")
	if err != nil {
		t.Error("Sharing error")
		return
	}
	err0 := ben.ReceiveFile("renamedFile1", "elise", magicString)
	if err0 != nil {
		t.Error("Ben should be able to receive this file")
		return
	}
	revokeErr := elise.RevokeFile("file1", "ben")
	if revokeErr != nil {
		t.Error("Failed to revoke file access")
		return
	}
	bLoadFileA, err := ben.LoadFile("renamedFile1")
	_ = bLoadFileA
	if err == nil {
		t.Error("Revoked file access: Ben should not be able to load this file")
		return
	}
	




}
