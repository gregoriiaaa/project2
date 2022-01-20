package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

/********************************* Basic Tests (provided to me) *********************************/

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(false)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	_ = u
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
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
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
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

/**************************************** Test InitUser ****************************************/

// Test Functionality
func TestInitFunc(t *testing.T) {
	clear()
	t.Log("Initialization Functionality Test")

	userlib.SetDebugStatus(false)

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	if alice == nil {
		t.Error("Failed to return pointer to userdata.")
		return
	}

	//Test alice Public Keys were successfully Stored
	keystoreMap := userlib.KeystoreGetMap()
	keysPerUser := len(keystoreMap)
	if keysPerUser < 2 {
		t.Error("There is currently one user, so there should be at least 2 keys on Keystore.")
		return
	}

	//Test initializing a user with same password as somebody else
	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize a user with same password as somebody else", err)
		return
	}
	if bob == nil {
		t.Error("Failed to return pointer to userdata.")
		return
	}

	//Test bob's Public Keys were successfully Stored, there should be twice the amount of keys
	// there were on the last check
	keystoreMap = userlib.KeystoreGetMap()
	if len(keystoreMap) != 2*keysPerUser {
		t.Error("Keys on Keystore must be constant to number of users.")
		return
	}

	//alice and bob should not be the same user
	if alice == bob {
		t.Error("alice and bob should not be the same user.")
		return
	}

	//Test initializing a user with a very similar username as somebody else
	bop, err := InitUser("bop", "fubar")
	if err != nil {
		t.Error("Failed to initialize a user with a very similar username as somebody else", err)
		return
	}
	if bop == nil {
		t.Error("Failed to return pointer to userdata.")
		return
	}

	//bob and bop should not be the same user
	if bob == bop {
		t.Error("bob and bop should not be the same user.")
		return
	}

	//Test bop's Public Keys were successfully Stored, there should be thrice the amount of keys
	// there were on the last check
	keystoreMap = userlib.KeystoreGetMap()
	if len(keystoreMap) != 3*keysPerUser {
		t.Error("Keys on Keystore must be constant to number of users.")
		return
	}

	//Test initializing a user with a same username (with a capital letter instead) as somebody else
	alice2, err := InitUser("Alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize a user with the same username (with a capital letter instead) as somebody else", err)
		return
	}
	if alice2 == nil {
		t.Error("Failed to return pointer to userdata.")
		return
	}

	//alice and Alice should not be the same user
	if alice == alice2 {
		t.Error("alice and Alice should not be the same user.")
		return
	}

	//Test Alice's Public Keys were successfully Stored, there should be 4x the amount of keys
	// there were on the last check
	keystoreMap = userlib.KeystoreGetMap()
	if len(keystoreMap) != 4*keysPerUser {
		t.Error("Keys on Keystore must be constant to number of users.")
		return
	}

}

// Test for Correct Error Handling
func TestInitErrors(t *testing.T) {
	t.Log("Initialization Error Handling Test")
	userlib.SetDebugStatus(false)

	//Test throwing error for empty password and username
	u, err := InitUser("", "the-password-is-password")
	if err == nil {
		t.Error("Failed to throw error for empty username.")
		return
	}
	if u != nil {
		t.Error("Failed to return nil.")
		return
	}
	u, err = InitUser("uSeRNaME", "")
	if err == nil {
		t.Error("Failed to throw error for empty password.")
		return
	}
	if u != nil {
		t.Error("Failed to return nil.")
		return
	}

	//Test throwing error for initializing a user that already exists
	u, err = InitUser("alice", "fubar")
	if err == nil {
		t.Error("Failed to throw error for initializing a user that already exists", err)
		return
	}
	if u != nil {
		t.Error("Failed to return nil.")
		return
	}

	//Test throwing error for initializing a user with a NOT unique username
	u, err = InitUser("alice", "potato")
	if err == nil {
		t.Error("Failed to throw error for initializing a user with a NOT unique username", err)
		return
	}
	if u != nil {
		t.Error("Failed to return nil.")
		return
	}

}

/**************************************** Test GetUser ****************************************/

// Test Functionality
func TestGetUserFunc(t *testing.T) {
	clear()
	t.Log("GetUser Functionality Test")

	userlib.SetDebugStatus(false)

	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "bufar")

	aliceS1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user for session 1.", err)
		return
	}
	if aliceS1 == nil {
		t.Error("Failed to return pointer to userdata.", err)
		return
	}

	//Test Correctness
	if !reflect.DeepEqual(alice, aliceS1) {
		t.Error("Got incorrect userdata.")
		return
	}

	bobS1, err := GetUser("bob", "bufar")
	if err != nil {
		t.Error("Failed to get user for session 1.", err)
		return
	}
	if bobS1 == nil {
		t.Error("Failed to return pointer to userdata.", err)
		return
	}

	//Test Correctness
	if !reflect.DeepEqual(bob, bobS1) {
		t.Error("Got incorrect userdata.")
		return
	}

	aliceS2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user for session 2.", err)
		return
	}
	if aliceS2 == nil {
		t.Error("Failed to return pointer to userdata.", err)
		return
	}

	//Test Correctness
	if !reflect.DeepEqual(alice, aliceS2) {
		t.Error("Got incorrect userdata.")
		return
	}

	bobS2, err := GetUser("bob", "bufar")
	if err != nil {
		t.Error("Failed to get user for session 1.", err)
		return
	}
	if bobS2 == nil {
		t.Error("Failed to return pointer to userdata.", err)
		return
	}

	//Test Correctness
	if !reflect.DeepEqual(bob, bobS2) {
		t.Error("Got incorrect userdata.")
		return
	}

}

// Test for Correct Error Handling
func TestGetUserErrors(t *testing.T) {
	t.Log("GetUser Correct Error Handling Test")

	userlib.SetDebugStatus(false)

	//Test nonexistant user
	u, err := GetUser("nonexistant", "fubar")
	if err == nil {
		t.Error("Failed to recognize nonexistant user.")
		return
	}
	if u != nil {
		t.Error("Failed to return nil.")
		return
	}

	//Test invalid password
	u, err = GetUser("alice", "Fubar")
	if err == nil {
		t.Error("Failed to recognize incorrect password.")
		return
	}
	if u != nil {
		t.Error("Failed to return nil.")
		return
	}

	//Test invalid username
	u, err = GetUser("Bob", "bufar")
	if err == nil {
		t.Error("Failed to recognize incorrect username.")
		return
	}
	if u != nil {
		t.Error("Failed to return nil.")
		return
	}

}

// Test Security
func TestGetUserSecurity(t *testing.T) {
	clear()
	t.Log("GetUser Security Test")

	userlib.SetDebugStatus(false)

	InitUser("alice", "fubar")
	aliceData := make(map[userlib.UUID]struct{})

	dsMap := userlib.DatastoreGetMap()

	for entry := range dsMap {
		aliceData[entry] = struct{}{}
	}

	InitUser("bob", "bufar")
	bobData := make(map[userlib.UUID]struct{})

	for entry := range dsMap {
		_, exists := aliceData[entry]
		if !exists {
			bobData[entry] = struct{}{}
		}
	}
	// t.Log(dsMap)
	// t.Log(aliceData)
	// t.Log(bobData)

	// Mallory messes with Alice's data
	for entry := range aliceData {
		dsMap[entry] = []byte("gEt ReCKtd")
	}

	// Alice attempts to log in
	alice, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("Failed to recognize compromised userdata.")
		return
	}
	if alice != nil {
		t.Error("Failed to return nil.")
		return
	}

	// Bob can still log in
	bob, err := GetUser("bob", "bufar")
	if err != nil {
		t.Error("Failed to get userdata.")
		return
	}
	if bob == nil {
		t.Error("Failed to return pointer to userdata.")
		return
	}

	// Mallory messes with Bob's data
	for entry := range bobData {
		dsMap[entry] = []byte("gEt ReCKtd")
	}

	// Bob attempts to log in
	bob, err = GetUser("bob", "bufar")
	if err == nil {
		t.Error("Failed to recognize compromised userdata.")
		return
	}
	if bob != nil {
		t.Error("Failed to return nil.")
		return
	}

}

/*************************************** Test StoreFile ***************************************/

// Test Functionality
func TestSingleUserStorageFunc(t *testing.T) {
	clear()
	t.Log("SingleUserStorage Functionality Test")

	userlib.SetDebugStatus(false)

	f1 := []byte("content")
	f2 := []byte("different content")

	// Alice starts a user session by authenticating to the client.
	aliceS1, _ := InitUser("user_alice", "password1")

	//Get number of Public Keys per user
	keystoreMap := userlib.KeystoreGetMap()
	keysPerUser := len(keystoreMap)

	// Bob starts a user session by authenticating to the client.
	bobS1, _ := InitUser("user_bob", "password2")

	// Alice stores byte slice f1 with name "filename" and Bob stores byte slice
	// f2 also with name "filename".
	err := aliceS1.StoreFile("filename", f1)
	if err != nil {
		t.Error("Failed to store alice's file.")
		return
	}
	err = bobS1.StoreFile("filename", f2)
	if err != nil {
		t.Error("Failed to store bob's file.")
		return
	}

	// Alice and Bob each confirm that they can load the file they previously
	// stored and that the file contents is the same.
	f1_loaded, _ := aliceS1.LoadFile("filename")
	f2_loaded, _ := bobS1.LoadFile("filename")
	if !reflect.DeepEqual(f1, f1_loaded) {
		t.Error("Alice's loaded file contents are different from original file.")
		return
	}
	if !reflect.DeepEqual(f2, f2_loaded) {
		t.Error("Bob's loaded file contents are different from original file.")
		return
	}

	// Bob creates a second user session by authenticating to the client again.
	bobS2, _ := GetUser("user_bob", "password2")

	// Bob stores byte slice f2 with name "newfile" using his second user
	// session.
	err = bobS2.StoreFile("newfile", f2)
	if err != nil {
		t.Error("Failed to store bob's file.")
		return
	}

	// Bob loads "newfile" using his first user session. Notice that Bob does
	// not need to reauthenticate. File changes must be available to all active
	// sessions for a given user.
	f2_newfile, _ := bobS1.LoadFile("newfile")

	if !reflect.DeepEqual(f2, f2_newfile) {
		t.Error("Bob's loaded file contents are different from original file.")
		return
	}

	// Test Bob can overwrite file
	newContent := []byte("bloop")
	err = bobS1.StoreFile("filename", newContent)
	if err != nil {
		t.Error("Failed to overwrite.")
		return
	}
	f2_loaded, err = bobS1.LoadFile("filename")
	if !reflect.DeepEqual(newContent, f2_loaded) {
		t.Error("Failed to overwrite with correct data.")
		return
	}

	// Bob loads overwritten file from his session 2
	f2_loaded, _ = bobS2.LoadFile("filename")

	if !reflect.DeepEqual(newContent, f2_loaded) {
		t.Error("Bob's loaded file contents are different from original file.")
		return
	}

	// Alice stores a file with an empty filename
	content := []byte("file content")
	err = aliceS1.StoreFile("", content)
	if err != nil {
		t.Error("Failed to store a file with an empty filename.")
		return
	}
	emptyFile, err := aliceS1.LoadFile("")
	if !reflect.DeepEqual(content, emptyFile) {
		t.Error("Failed to correclty store/load file with empty filename.")
		return
	}

	//Test Number of Public Keys stayed constant
	keystoreMap = userlib.KeystoreGetMap()
	if len(keystoreMap) != 2*keysPerUser { //two users
		t.Error("Keys on Keystore must be constant to number of users.")
		return
	}

}

func TestSingleUserStoragePersistence(t *testing.T) {
	t.Log("SingleUserStorage Persistence Test")

	userlib.SetDebugStatus(false)

	alice, _ := GetUser("user_alice", "password1")

	// "filename" --> []byte("content")
	content := []byte("content")

	// Alice is able to load file after logging out and loggin back in
	file, err := alice.LoadFile("filename")
	if err != nil {
		t.Error("Failed to load Alice's file from previous login.")
		return
	}
	if !reflect.DeepEqual(content, file) {
		t.Error("Alice's file contents are incorrect.")
		return
	}

}

// Test for Correct Error Handling
func TestSingleUserStorageErrors(t *testing.T) {
	t.Log("SingleUserStorage Error Handling Test")

	userlib.SetDebugStatus(false)

	alice, _ := GetUser("user_alice", "password1")

	// Alice gets an error when trying to load a file that does not exist in her
	// namespace.
	f, err := alice.LoadFile("nonexistent")
	if err == nil {
		t.Error("Failed to throw error for downloading a nonexistent file.")
		return
	}
	if f != nil {
		t.Error("Failed to return nil.")
		return
	}

}

// Test Security
func TestSingleUserStorageSecurity(t *testing.T) {
	clear()
	t.Log("SingleUserStorage Security Test")

	userlib.SetDebugStatus(false)

	alice, _ := InitUser("alice", "fubar")

	dsMap := userlib.DatastoreGetMap()

	// Collect Alice's user data
	aliceData := make(map[userlib.UUID]struct{})
	for entry := range dsMap {
		aliceData[entry] = struct{}{}
	}

	bob, _ := InitUser("bob", "bufar")

	// Collect Bob's user data
	bobData := make(map[userlib.UUID]struct{})
	for entry := range dsMap {
		_, exists := aliceData[entry]
		if !exists {
			bobData[entry] = struct{}{}
		}
	}
	// t.Log(dsMap)
	// t.Log(aliceData)
	// t.Log(bobData)

	// Alice stores a file
	alice.StoreFile("filename", []byte("file content"))

	// Collect Alice's file data
	aliceFileData := make(map[userlib.UUID]struct{})
	for entry := range dsMap {
		_, exists1 := aliceData[entry]
		_, exists2 := bobData[entry]
		if !exists1 && !exists2 {
			aliceFileData[entry] = struct{}{}
		}
	}

	// Bob stores a file
	bob.StoreFile("namefile", []byte("content file"))

	// Collect Bob's file data
	bobFileData := make(map[userlib.UUID]struct{})
	for entry := range dsMap {
		_, exists1 := aliceData[entry]
		_, exists2 := bobData[entry]
		_, exists3 := aliceFileData[entry]
		if !exists1 && !exists2 && !exists3 {
			bobFileData[entry] = struct{}{}
		}
	}

	// t.Log(dsMap)
	// t.Log(aliceData)
	// t.Log(bobData)
	// t.Log(aliceFileData)
	// t.Log(bobFileData)

	// Mallory messes with Alice's FILE data
	for entry := range aliceFileData {
		dsMap[entry] = []byte("gEt ReCKtd")
	}

	// Alice attempts to load her file
	aliceFile, err := alice.LoadFile("filename")
	if err == nil {
		t.Error("Failed to recognize compromised file data.")
		return
	}
	if aliceFile != nil {
		t.Error("Failed to return nil.")
		return
	}

	// Bob can still load his file
	bobFile, err := bob.LoadFile("namefile")
	if err != nil {
		t.Error("Failed to get userdata.")
		return
	}
	if !reflect.DeepEqual([]byte("content file"), bobFile) {
		t.Error("Incorrect file contents for Bob.")
		return
	}

	// Mallory messes with Bob's data
	for entry := range bobFileData {
		dsMap[entry] = []byte("gEt ReCKtd")
	}

	// Bob attempts to load his file
	bobFile, err = bob.LoadFile("namefile")
	if err == nil {
		t.Error("Failed to recognize compromised file data.")
		return
	}
	if bobFile != nil {
		t.Error("Failed to return nil.")
		return
	}

}

/*************************************** Test LoadFile ***************************************/

// Test Functionality

// Test for Correct Error Handling

// Test Security

/************************************** Test AppendFile **************************************/

// Test Functionality
func TestAppendFunc(t *testing.T) {
	clear()
	t.Log("Append Functionality Test")

	userlib.SetDebugStatus(false)

	f1 := []byte("content")
	append1 := []byte("more content")
	append2 := []byte("mas more content")
	append3 := []byte("even mas more content")

	_, _ = InitUser("user_alice", "potato")

	// Alice starts two user sessions by authenticating to the client.
	alice_session_1, _ := GetUser("user_alice", "potato")
	alice_session_2, _ := GetUser("user_alice", "potato")

	// Test error is thrown when file does not exists
	err := alice_session_1.AppendFile("nonexistent", append1)
	if err == nil {
		t.Error("Failed to throw error when file does not exists.", err)
		return
	}

	err = alice_session_1.StoreFile("file1", f1)
	if err != nil {
		t.Error("Failed to store Alice's file1.", err)
		return
	}

	// Test append with a single user session
	err = alice_session_1.AppendFile("file1", append1)
	if err != nil {
		t.Error("Failed to append to Alice's file1.", err)
		return
	}
	loadedFile, err := alice_session_1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load Alice's file1.", err)
		return
	}
	// t.Log("f1: ", f1)
	// t.Log("append1: ", append1)
	// t.Log("loadedFile: ", loadedFile)
	if !reflect.DeepEqual(string(loadedFile), string(f1)+string(append1)) {
		t.Error("Alice's file1 is incorrect.")
		return
	}

	// Test second append with the same single user session
	err = alice_session_1.AppendFile("file1", append2)
	if err != nil {
		t.Error("Failed to append to Alice's file1.", err)
		return
	}
	loadedFile, err = alice_session_1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load Alice's file1.", err)
		return
	}
	// t.Log("f1: ", f1)
	// t.Log("append1: ", append1)
	// t.Log("append2: ", append2)
	// t.Log("loadedFile: ", loadedFile)
	if !reflect.DeepEqual(string(loadedFile), string(f1)+string(append1)+string(append2)) {
		t.Error("Alice's file1 is incorrect.")
		return
	}

	// Test third append with a different user session
	err = alice_session_2.AppendFile("file1", append3)
	if err != nil {
		t.Error("Failed to append to Alice's file1.", err)
		return
	}
	loadedFile, err = alice_session_1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load Alice's file1.", err)
		return
	}
	// t.Log("f1: ", f1)
	// t.Log("append1: ", append1)
	// t.Log("append2: ", append2)
	// t.Log("append3: ", append3)
	// t.Log("loadedFile: ", loadedFile)
	if !reflect.DeepEqual(string(loadedFile), string(f1)+string(append1)+string(append2)+string(append3)) {
		t.Error("Alice's file1 is incorrect.")
		return
	}

	// Test Append Efficiency
	var bigFile [1000]byte
	var midBandwidth int
	midCheckpoint := 1000
	endCheck := 10000

	for i := 0; i < len(bigFile); i++ {
		bigFile[i] = byte(i % 255)
	}
	alice_session_1.StoreFile("bigFile", bigFile[:])
	userlib.DatastoreResetBandwidth()

	data := []byte("\nThis Data was appended ")
	dataLen := 0
	for i := 0; i < endCheck; i++ {
		alice_session_1.AppendFile("file1", data)
		dataLen += len(data)
		if i == midCheckpoint {
			midBandwidth = userlib.DatastoreGetBandwidth()
		}
		// data = append(data, data[:10]...)
	}

	endBandwitdth := userlib.DatastoreGetBandwidth()

	midPoint := midBandwidth / midCheckpoint
	endPoint := endBandwitdth / endCheck

	if (midPoint - endPoint) > 1 {
		t.Error("POOR APPEND EFFICIENCY: The mid to end appends took more bandwidth than the begining to mid appends.")
		return
	}

}

// Test for Correct Error Handling

// Test Security

/*************************************** Test ShareFile ***************************************/

// Test Functionality

// Test for Correct Error Handling

// Test Security

/************************************** Test ReceiveFile **************************************/

// Test Functionality

// Test for Correct Error Handling

// Test Security

/************************************** Test RevokeFile **************************************/

// Test Functionality

// Test for Correct Error Handling

// Test Security

func TestShareErrors(t *testing.T) {
	clear()

	userlib.SetDebugStatus(false)

	// Initialize two users
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

	// Start a second session for Bob
	u2_session2, _ := GetUser("bob", "foobar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	u.StoreFile("test-file", []byte("Testing persistence of this file."))

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	// Test alice cannot share a file that does not exists in her namespace
	_, err = u.ShareFile("nonexistent-file", "bob")
	if err == nil {
		t.Error("Failed to throw error for nonexistent file.")
		return
	}

	// Test alice cannot share a file with a user that does not exists
	_, err = u.ShareFile("file1", "nonexistant-user")
	if err == nil {
		t.Error("Failed to throw error for nonexistent user.")
		return
	}

	// Alice shared file with Bob
	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	// Bob receives file from Alice
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	// Check file was successfully shared
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	// Check Bob's session2 can see Alice's file
	v2, err = u2_session2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing for session2", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	// Check Bob can append to file
	append1 := []byte("this is bob's append")
	err = u2.AppendFile("file2", append1)
	if err != nil {
		t.Error("Failed to allow Bob to append to Alice's file.")
		return
	}

	// Check the file contents reflect what they should be for Alice and Bob
	v3 := append(v2, append1...)
	aliceV3, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file for Alice.")
		return
	}
	bobV3, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load file for Bob.")
		return
	}
	if !reflect.DeepEqual(v3, aliceV3) {
		t.Error("Alice's file contents are incorrect.")
		return
	}
	if !reflect.DeepEqual(v3, bobV3) {
		t.Error("Bob's file contents are incorrect.")
		return
	}

	// Check that Bob can overwrite the file
	v4 := []byte("Bob overwrote da file.")
	err = u2.StoreFile("file2", v4)
	if err != nil {
		t.Error("Failed to allow Bob to overwrite Alice's file.")
		return
	}

	// Check the file contents reflect what they should be for Alice and Bob
	aliceV4, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file for Alice.")
		return
	}
	bobV4, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load file for Bob.")
		return
	}
	if !reflect.DeepEqual(v4, aliceV4) {
		t.Error("Alice's file contents are incorrect.")
		return
	}
	if !reflect.DeepEqual(v4, bobV4) {
		t.Error("Bob's file contents are incorrect.")
		return
	}

	// Bob shares Alice's file with Charlie
	u3, _ := InitUser("charlie", "bufar")
	_ = u3.StoreFile("file1", []byte("Charlie's file1."))

	accessToken2, err := u2.ShareFile("file2", "charlie")
	if err != nil {
		t.Error("Failed to share file with Charlie from Bob.", err)
	}

	// Test Charlie cannot recieve file from Alice's share message to Bob
	err = u3.ReceiveFile("file3", "alice", accessToken)
	if err == nil {
		t.Error("Charlie should not be able to receive the share message from Alice to Bob.")
		return
	}

	// Test Charlie cannot recieve file from Bob with a filename that already exists in his
	// namespace.
	err = u3.ReceiveFile("file1", "bob", accessToken2)
	if err == nil {
		t.Error("Charlie cannot recieve file with filename that already exists in his namespace.", err)
		return
	}

	// Charlie recieves file from Bob.
	err = u3.ReceiveFile("file3", "bob", accessToken2)
	if err != nil {
		t.Error("Failed to receive the share message from Bob to Charlie.", err)
		return
	}

	// Check file was successfully shared
	charlieV4, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v4, charlieV4) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	// Check Charlie can append to file
	append2 := []byte("this is charlie's append")
	err = u3.AppendFile("file3", append2)
	if err != nil {
		t.Error("Failed Charlie's append.")
		return
	}

	// Check the file contents reflect what they should be for Alice, Bob, and Charlie
	v5 := append(v4, append2...)
	aliceV5, _ := u.LoadFile("file1")
	bobV5, _ := u2.LoadFile("file2")
	charlieV5, _ := u3.LoadFile("file3")
	if !reflect.DeepEqual(v5, aliceV5) {
		t.Error("Alice's file contents are incorrect.")
		return
	}
	if !reflect.DeepEqual(v5, bobV5) {
		t.Error("Bob's file contents are incorrect.")
		return
	}
	if !reflect.DeepEqual(v5, charlieV5) {
		t.Error("Bob's file contents are incorrect.")
		return
	}
}

// NOTE: TestRevoke does not clear the Datastore. This is to test revoking access from users who
// exists but are also offline.
func TestRevoke(t *testing.T) {
	userlib.SetDebugStatus(false)

	// Alice logs in
	alice, _ := GetUser("alice", "fubar")

	// Initialize a new user
	dora, _ := InitUser("dora", "the-exploradora")

	// Alice shares with Dora
	accessToken, err := alice.ShareFile("file1", "dora")
	if err != nil {
		t.Error("Failed to share file with Dora.", err)
		return
	}

	// Alice revokes access from Dora before Dora recieves
	err = alice.RevokeFile("file1", "dora")
	if err != nil {
		t.Error("Failed to revoke access from Dora.", err)
		return
	}

	// Dora tries to recieve file from Alice and read it
	err = dora.ReceiveFile("file4", "alice", accessToken)
	if err == nil {
		t.Error("Failed to revoke access from Dora.")
		return
	}
	_, err = dora.LoadFile("file4")
	if err == nil {
		t.Error("Failed to revoke access from Dora.")
		return
	}

	// Alice shares with Dora again
	accessToken2, err := alice.ShareFile("file1", "dora")
	if err != nil {
		t.Error("Failed to share file with Dora.", err)
		return
	}

	// Dora recieves file from Alice
	err = dora.ReceiveFile("file4", "alice", accessToken2)
	if err != nil {
		t.Error("Failed to recieve file from Alice.", err)
	}

	// Alice revokes Bob's access while he is offline
	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke access from Bob.", err)
		return
	}

	// Bob logs in and attempts to read Alice's file
	bob, _ := GetUser("bob", "foobar")
	_, err = bob.LoadFile("file2")
	if err == nil {
		t.Error("Failed to revoke Bob's direct access.")
		return
	}

	// Bob attempts to append and overwrite file
	err = bob.AppendFile("file2", []byte("Oh no you didn't, Alice."))
	if err == nil {
		t.Error("Failed to revoke Bob's direct access: Bob was able to append.")
		return
	}
	err = bob.StoreFile("file2", []byte("Rude."))
	if err == nil {
		t.Error("Failed to revoke Bob's direct access: Bob was able to overwrite file.")
		return
	}

	// Charlie logs in and attempts to read Alice's file which was shared by Bob
	charlie, _ := GetUser("charlie", "bufar")
	_, err = charlie.LoadFile("file3")
	if err == nil {
		t.Error("Failed to revoke Charlie's indirect access.")
		return
	}

	// Charlie attempts to append and overwrite file
	err = charlie.AppendFile("file3", []byte("What?"))
	if err == nil {
		t.Error("Failed to revoke Charlie's indirect access: Charlie was able to append.")
		return
	}
	err = charlie.StoreFile("file3", []byte("Why?"))
	if err == nil {
		t.Error("Failed to revoke Charlie's indirect access: Charlie was able to overwrite file.")
		return
	}

	// Dora's access remains unaffected
	_, err = dora.LoadFile("file4")
	if err != nil {
		t.Error("Failed to leave Dora's direct access unaffected.")
		return
	}
	err = dora.AppendFile("file4", []byte("lul"))
	if err != nil {
		t.Error("Failed to leave Dora's direct access unaffected.")
		return
	}
}

/*
********************************************
**       	     My API Test			  **
********************************************
 */

func TestDefense(t *testing.T) {
	clear()
	userlib.SetDebugStatus(false)

	//Initialize alice
	alice, _ := InitUser("alice", "fubar")

	//Alice stores a file
	file1 := []byte("Meet with Bob at 1900.")
	_ = alice.StoreFile("file1", file1)

	//Mallory Attacks the Datastore
	dsMap := userlib.DatastoreGetMap()
	// t.Log("Datastore before attack: ", dsMap)
	for e, v := range dsMap {
		i := len(v) - 1
		userlib.DatastoreSet(e, append(v[:i], byte('Z')))
		// dsMap[e] = append(v[:i], byte('Z'))
	}
	// t.Log("Datastore after attack: ", dsMap)
	// t.Log("Direct call to datastoregetmap: ", userlib.DatastoreGetMap())

	//Alice attempts to interact with file
	_, err := alice.LoadFile("file1")
	if err == nil {
		t.Error("Failed to recognize compromised integrity.")
		return
	}
	err = alice.AppendFile("file1", []byte("Location: Sproul"))
	if err == nil {
		t.Error("Failed to recognize compromised integrity.")
		return
	}
	err = alice.StoreFile("file1", []byte("Meeting was cancelled."))
	if err == nil {
		t.Error("Failed to recognize compromised integrity.")
		return
	}

	clear()
	userlib.SetDebugStatus(false)

	//Initialize users
	alice, _ = InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "bufar")

	//Alice stores a file and shares it with Bob
	_ = alice.StoreFile("file1", file1)
	accessToken, _ := alice.ShareFile("file1", "bob")

	//Mallory Attacks Message containing AccessToken
	fraugilantAT := uuid.New()

	//Bob tries to recieve Alice's share invitation with fraugilantAT
	err = bob.ReceiveFile("file2", "alice", fraugilantAT)
	if err == nil {
		t.Error("Failed to recognize compromised integrity.")
		return
	}

	//Mallory Attacks the Share Invitation saved on the Datastore
	dsMap = userlib.DatastoreGetMap()
	invitation := dsMap[accessToken]
	i := len(invitation) - 7
	dsMap[accessToken] = append(invitation[:i], []byte("POTATO")...)

	//Bob tries to recieve Alice's share invitation
	err = bob.ReceiveFile("file2", "alice", accessToken)
	if err == nil {
		t.Error("Failed to recognize compromised integrity.")
		return
	}

}

/*
********************************************
**        My Helper Function Tests        **
********************************************
 */

// func TestGetSymKeys(t *testing.T) {
// 	t.Log("GetSymKeys test")

// 	userlib.SetDebugStatus(false)

// 	//Test error is thrown for parent key with length that is not 16
// 	parentKey := userlib.RandomBytes(0)
// 	_, _, err := getSymKeys(parentKey)
// 	if err != nil {
// 		t.Error("Failed to throw error for empty parent key.")
// 		return
// 	}
// 	parentKey = userlib.RandomBytes(15)
// 	_, _, err = getSymKeys(parentKey)
// 	if err != nil {
// 		t.Error("Failed to throw error for parent key of length 15.")
// 		return
// 	}
// 	parentKey = userlib.RandomBytes(17)
// 	_, _, err = getSymKeys(parentKey)
// 	if err != nil {
// 		t.Error("Failed to throw error for parent key of length 17.")
// 		return
// 	}

// 	//Test determinism
// 	parentKey = userlib.RandomBytes(16)
// 	ek1, mk1, _ := getSymKeys(parentKey)
// 	ek2, mk2, _ := getSymKeys(parentKey)
// 	if !reflect.DeepEqual(ek1, ek2) || !reflect.DeepEqual(mk1, mk2) {
// 		t.Error("Failed to deterministically create encryption and mac key from parent key.")
// 		return
// 	}
// 	//Test length of keys
// 	if len(ek1) != userlib.AESKeySizeBytes {
// 		t.Error("Failed to create encryption key with corret size of AESKeySize = 16.")
// 		return
// 	}
// 	if len(mk1) != userlib.AESKeySizeBytes {
// 		t.Error("Failed to create mac key with corret size of AESKeySize = 16.")
// 		return
// 	}

// 	//Test two different parent keys created different encryption and mac keys
// 	parentKey1 := userlib.RandomBytes(16)
// 	parentKey2 := userlib.RandomBytes(16)
// 	ek1, mk1, _ = getSymKeys(parentKey1)
// 	ek2, mk2, _ = getSymKeys(parentKey2)
// 	if reflect.DeepEqual(ek1, ek2) || reflect.DeepEqual(mk1, mk2) {
// 		t.Error("Failed to create different encryption and mac keys from two different parent keys.")
// 		return
// 	}

// }

// func TestGetAuthKeys(t *testing.T) {
// 	t.Log("GetAuthKeys test")

// 	userlib.SetDebugStatus(false)

// 	//Test error is thrown for empty username and/or password
// 	string1, empty := "potatoes", ""
// 	_, err := getAuthParentKey(string1, empty)
// 	if err != nil {
// 		t.Error("Failed to throw error for empty password.")
// 		return
// 	}
// 	_, err = getAuthParentKey(empty, string1)
// 	if err != nil {
// 		t.Error("Failed to throw error for empty username.")
// 		return
// 	}
// 	_, err = getAuthParentKey(empty, empty)
// 	if err != nil {
// 		t.Error("Failed to throw error for empty username and password.")
// 		return
// 	}

// 	//Test determinism
// 	userParentKey1, _ := getAuthParentKey(string1, string1)
// 	userParentKey2, _ := getAuthParentKey(string1, string1)
// 	if !reflect.DeepEqual(userParentKey1, userParentKey2) {
// 		t.Error("Failed to deterministically create encryption and mac key from the same username and password.")
// 		return
// 	}
// 	string2 := "baked"
// 	ek1, mk1, _ = getAuthKeys(string2, string1)
// 	ek2, mk2, _ = getAuthKeys(string2, string1)
// 	if !reflect.DeepEqual(ek1, ek2) || !reflect.DeepEqual(mk1, mk2) {
// 		t.Error("Failed to deterministically create encryption and mac key from username and password.")
// 		return
// 	}
// 	string3 := "bacon"
// 	ek2, mk2, _ = getAuthKeys(string3, string1)
// 	if reflect.DeepEqual(ek1, ek2) || reflect.DeepEqual(mk1, mk2) {
// 		t.Error("Failed to create different encryption and mac keys from different username and same password.")
// 		return
// 	}
// 	string4 := "sushiroll"
// 	ek2, mk2, _ = getAuthKeys(string3, string4)
// 	if reflect.DeepEqual(ek1, ek2) || reflect.DeepEqual(mk1, mk2) {
// 		t.Error("Failed to create different encryption and mac keys from different username and different password.")
// 		return
// 	}

// 	//Test length of keys
// 	if len(ek1) != userlib.AESKeySizeBytes {
// 		t.Error("Failed to create encryption key with corret size of AESKeySize = 16.")
// 		return
// 	}
// 	if len(mk1) != userlib.AESKeySizeBytes {
// 		t.Error("Failed to create mac key with corret size of AESKeySize = 16.")
// 		return
// 	}

// }

// func TestGetEncrypted(t *testing.T) {
// 	clear()
// 	t.Log("GetVerified test")

// 	userlib.SetDebugStatus(false)

// 	msg := []byte("Hello World") // size = 11 bytes
// 	t.Log("MSG: ", msg)

// 	ek := userlib.RandomBytes(16)

// 	encryptedMsg, err1 := getEncrypted(msg, ek)
// 	if err1 != nil {
// 		t.Error("Failed to encrypt MSG.", err1)
// 		return
// 	}
// 	if len(encryptedMsg) != 32 { // pt (11) + pad (5) + iv (16) = 32
// 		t.Error("Failed to correctly encrypt MSG. Size of encryption: ", len(encryptedMsg))
// 		return
// 	}

// }

// func TestGetMACed(t *testing.T) {
// 	clear()
// 	t.Log("GetVerified test")

// 	userlib.SetDebugStatus(false)

// 	msg := []byte("Get to tha choppa!")
// 	// t.Log("MSG: ", msg)

// 	msgSize := len(msg)
// 	mk := userlib.RandomBytes(16)

// 	tag, _ := userlib.HMACEval(mk, msg)
// 	// t.Log("TAG: ", tag)

// 	msgWithTag := make([]byte, msgSize+64)
// 	copy(msgWithTag, msg)
// 	copy(msgWithTag[msgSize:], tag)

// 	macedMsg, err1 := getMACed(msg, mk)
// 	if err1 != nil {
// 		t.Error("Failed to MAC a message.", err1)
// 		return
// 	}
// 	if !reflect.DeepEqual(macedMsg, msgWithTag) {
// 		t.Error("Failed to correctly MAC amessage.")
// 		t.Error("MACed MSG: ", macedMsg)
// 		t.Error("MSG with tag attached: ", msgWithTag)
// 		return
// 	}
// }

// func TestEncThenMac(t *testing.T) {
// 	t.Log("EncThenMac test")

// 	userlib.SetDebugStatus(false)

// 	//Test error is thrown for empty message
// 	msg := []byte("")
// 	_, err := encryptThenMac(msg, userlib.RandomBytes(16))
// 	if err != nil {
// 		t.Error("Failed to throw error for empty message. ")
// 		return
// 	}

// 	msg = []byte("Hello World")

// 	//Test correctness
// 	parentKey := userlib.RandomBytes(16)
// 	msgBytes := []byte(msg) //msg="Hello World" has a size of 11 bytes
// 	result, _ := encryptThenMac(msgBytes, parentKey)
// 	if len(result) != 96 {
// 		t.Error("Inccorect length of result.") //11 (pt) + 5 (pad) + 16 (iv) + 64 (tag) = 96 bytes
// 		return
// 	}

// }

// func TestGetVerified(t *testing.T) {
// 	clear()
// 	t.Log("GetVerified test")

// 	userlib.SetDebugStatus(false)

// 	msg := []byte("Get to tha choppa!")
// 	// t.Log("MSG: ", msg)

// 	msgSize := len(msg)
// 	mk := userlib.RandomBytes(16)

// 	tag, _ := userlib.HMACEval(mk, msg)
// 	// t.Log("TAG: ", tag)

// 	msgWithTag := make([]byte, msgSize+64)
// 	copy(msgWithTag, msg)
// 	copy(msgWithTag[msgSize:], tag)
// 	// t.Log("MSG with tag attatched: ", msgWithTag)

// 	verifiedMsg, err1 := getVerified(msgWithTag, mk)
// 	if err1 != nil {
// 		t.Error("Failed to verify an untampered message.", err1)
// 		return
// 	}
// 	if !reflect.DeepEqual(msg, verifiedMsg) {
// 		t.Error("Failed to correctly return the message.", err1)
// 		return
// 	}

// 	tamperedMsg := msg
// 	tamperedMsg[10] = byte('e')
// 	tamperedMsgWithTag := make([]byte, msgSize+64)
// 	copy(tamperedMsgWithTag, msg)
// 	copy(tamperedMsgWithTag[msgSize:], tag)
// 	// t.Log("Tampered MSG with tag attatched: ", msgWithTag)
// 	_, err2 := getVerified(tamperedMsgWithTag, mk)
// 	if err2 != nil {
// 		t.Error("Failed to detect compromised message.")
// 		return
// 	}

// }

// func TestGetDecrypted(t *testing.T) {
// 	clear()
// 	t.Log("GetDecrypted test")

// 	userlib.SetDebugStatus(false)

// 	msg := []byte("Hello World") // size = 11 bytes
// 	ek := userlib.RandomBytes(16)
// 	encrypted, err := getEncrypted(msg, ek)
// 	if err != nil {
// 		t.Error("Failed to encrypt.", err)
// 		return
// 	}
// 	decrypted, err := getDecrypted(encrypted, ek)
// 	if err != nil {
// 		t.Error("Failed to decrypt.", err)
// 		return
// 	}
// 	if !reflect.DeepEqual(msg, decrypted) {
// 		t.Error("Failed to correctly decrypt.")
// 		t.Error("MSG: ", msg)
// 		t.Error("Decrypted MSG: ", decrypted)
// 		return
// 	}

// }

// func TestEncDec(t *testing.T) {
// 	t.Log("Encryption and Decryption test")

// 	userlib.SetDebugStatus(false)

// 	msg := []byte("This is a very secret secret.")
// 	parentKey := userlib.RandomBytes(16)

// 	crypted, _ := encryptThenMac(msg, parentKey)
// 	decrypted, err := verifyThendecrypt(crypted, parentKey)
// 	if !reflect.DeepEqual(msg, decrypted) {
// 		t.Error("Nope.", err)
// 		return
// 	}

// 	tampered := crypted
// 	tampered[10] = byte('c')
// 	_, err = verifyThendecrypt(tampered, parentKey)
// 	if err != nil {
// 		t.Error("Failed to detect compromised integrity.")
// 		return
// 	}

// }
