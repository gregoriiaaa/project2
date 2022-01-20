package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"reflect"

	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {

	//Verify parameters
	if len(username) < 1 || len(password) < 1 {
		return nil, Error("Username and password cannot be empty.")
	}
	//!Debugging
	userlib.DebugMsg("Username: %v, Password: %v", username, password)
	//!

	//Check for existing user
	userUUID := bytesToUUID(userlib.Hash([]byte(username)))
	_, exists := userlib.DatastoreGet(userUUID)
	if exists {
		return nil, Error("User already exists.")
	}

	//Initialize user struct
	var userdata User
	userdataptr = &userdata
	userdata.Username = username
	userdata.Key = userlib.RandomBytes(16)

	//Create RSA Encryption Public and Private Key Pair and store Public Key on Keystore
	var encPublicKey userlib.PKEEncKey
	encPublicKey, userdata.DecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userlib.KeystoreSet(username+"PKE", encPublicKey)
	//!Debugging
	// _, okay := userlib.KeystoreGet(username + "PKE")
	// userlib.DebugMsg("Successfully stored PKE EncKey in Keystore: %v", okay)
	//!

	//Create Digital Signature Public and Private Key Pair and store Public Key on Keystore
	var dsPublicKey userlib.DSVerifyKey
	userdata.SignKey, dsPublicKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet(username+"DS", dsPublicKey)
	//!Debugging
	// _, okay = userlib.KeystoreGet(username + "DS")
	// userlib.DebugMsg("Successfully stored DS Verify Key in Keystore: %v", okay)
	//!

	//Create user file cabinet, and ecrypt and save onto Datastore
	userdata.FCLocation = uuid.New()
	var fileCab FileCabinet
	fileCab.Cabinet = make(map[string]uuid.UUID)
	err = fileCab.StoreFileCabinet(&userdata)
	if err != nil {
		return nil, err
	}

	//Get authorization keys from password and username to save the user struct
	userParentKey, err := getAuthParentKey(username, password)
	if err != nil {
		return nil, err
	}

	//? maybe i can use the store json data method here for the user struct
	//Encrypt user struct
	userdataBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	encryptedUserdata, err := encryptThenMac(userdataBytes, userParentKey)
	if err != nil {
		return nil, err
	}

	//Save user struct onto Datastore
	userlib.DatastoreSet(userUUID, encryptedUserdata)
	//!Debugging
	_, okay := userlib.DatastoreGet(userUUID)
	userlib.DebugMsg("Successfully stored Userdata in Datastore: %v", okay)
	//!

	//End of my implementation

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	//Verify parameters
	if len(username) < 1 || len(password) < 1 {
		return nil, Error("Username and password cannot be empty.")
	}
	//!Debugging
	userlib.DebugMsg("Username: %v, Password: %v", username, password)
	//!

	//Get encrypted user bytes
	userUUID := bytesToUUID(userlib.Hash([]byte(username)))
	user, exists := userlib.DatastoreGet(userUUID)
	if !exists {
		return nil, Error("User with given username does not exists.")
	}

	//Decrypt user json data
	userParentKey, err := getAuthParentKey(username, password)
	if err != nil {
		return nil, err
	}
	userBytes, err := verifyThendecrypt(user, userParentKey)
	if err != nil {
		return nil, err
	}

	//Unmarshall user bytes to get User struct
	var userdata User
	err = json.Unmarshal(userBytes, &userdata)
	if err != nil {
		return nil, err
	}

	userdataptr = &userdata
	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	if userdata == nil {
		return Error("User is nil.")
	}

	//Open user's file cabinet
	var fc FileCabinet
	err = GetFileCabinet(userdata, &fc)
	if err != nil {
		return err
	}

	//!Debugging
	userlib.DebugMsg("FC: %v", fc)
	//!

	var fm FileManager
	//Prepare file's FileBlob
	var fb FileBlob
	fileLabel := hex.EncodeToString(userlib.Hash([]byte(userdata.Username + filename)))

	//If file doesn't exist, set up file's structs and save. Else, overwrite existing file.
	_, exists := fc.Cabinet[fileLabel]
	if !exists {
		//Create the new FileBlob for file
		fb.FMKey = userlib.RandomBytes(16)
		fb.FMLocation = uuid.New()
		fb.AuthUsers = make(map[string]AuthUser)
		fb.SharedToMe = false

		//Add FileBlob to FileCabinet and Store on Datastore
		fbLocation := uuid.New()
		fc.Cabinet[fileLabel] = fbLocation
		//!Debugging
		// userlib.DebugMsg("Cabinet within store function: %v", fc.Cabinet)
		//!
		err = fb.StoreFileBlob(filename, userdata, &fc)
		if err != nil {
			return err
		}

		//Create file's FileManager
		var fm FileManager
		fm.FileKey = userlib.RandomBytes(16)
		fm.LastFileNodeLoc = uuid.New()
		fm.HasAppends = false

		//Create file node with given data and Store on Datastore
		var node FileNode
		node.FileData = data
		node.DataSize = len(data)
		node.Prev = uuid.Nil
		err = node.StoreFileNode(fm.LastFileNodeLoc, &fm)
		if err != nil {
			return err
		}

		//Update total file size and store file manager
		fm.TotalByteSize = node.DataSize
		err = fm.StoreFileManager(&fb)
		if err != nil {
			return err
		}

		//File has been stored onto the Datastore

	} else {
		//Overwrite existing file and corresponding file structs.
		fb, fm, err = GetFileStructs(filename, userdata, &fc)
		if err != nil {
			return err
		}

		//!Debugging
		// userlib.DebugMsg("FM: %v", fm)
		// userlib.DebugMsg("FB: %v", fb)
		//!

		//Create new file node with given data
		var fileNode FileNode
		fileNode.FileData = data
		fileNode.DataSize = len(data)
		fileNode.Prev = uuid.Nil
		nodeLocation := uuid.New()
		err = fileNode.StoreFileNode(nodeLocation, &fm)
		if err != nil {
			return err
		}

		//Update FileManager, overwriting the previous filedata
		fm.LastFileNodeLoc = nodeLocation
		fm.TotalByteSize = fileNode.DataSize
		fm.HasAppends = false

		//Store updated FileManager
		err = fm.StoreFileManager(&fb)
		if err != nil {
			return err
		}

		//!Debugging
		userlib.DebugMsg("FM: %v", fm)
		userlib.DebugMsg("FB: %v", fb)
		//!

		//File was overwritten with new data
	}

	//!Debugging
	// userlib.DebugMsg("FB: %v", fb)
	//!

	//Store File Blob
	err = fb.StoreFileBlob(filename, userdata, &fc)
	if err != nil {
		return err
	}

	//Store updated FileCabinet
	err = fc.StoreFileCabinet(userdata)
	if err != nil {
		return err
	}

	return nil
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//Open user's FileCabinet
	var fc FileCabinet
	err = GetFileCabinet(userdata, &fc)
	if err != nil {
		return err
	}

	//Find file
	fileLabel, err := fc.getFileLabel(filename, userdata.Username)
	if err != nil {
		return err
	}
	_, exists := fc.Cabinet[fileLabel]
	if !exists {
		return Error("File with given filename does not exist.")
	}

	//Get file's structs
	fb, fm, err := GetFileStructs(filename, userdata, &fc)
	if err != nil {
		return err
	}

	//!Debugging
	// userlib.DebugMsg("FB: %v", fb)
	// userlib.DebugMsg("FM: %v", fm)
	//!

	//Create node for file append and store
	var newNode FileNode
	newNode.FileData = data
	newNode.DataSize = len(data)
	newNode.Prev = fm.LastFileNodeLoc
	newNodeLocation := uuid.New()
	err = newNode.StoreFileNode(newNodeLocation, &fm)
	if err != nil {
		return err
	}

	//Update FileManager
	fm.HasAppends = true
	fm.TotalByteSize += newNode.DataSize
	fm.LastFileNodeLoc = newNodeLocation
	err = fm.StoreFileManager(&fb)
	if err != nil {
		return err
	}
	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	//Open user's FileCabinet
	var fc FileCabinet
	err = GetFileCabinet(userdata, &fc)
	if err != nil {
		return nil, err
	}

	//Find file
	fileLabel, err := fc.getFileLabel(filename, userdata.Username)
	if err != nil {
		return nil, err
	}
	//!Debugging
	// userlib.DebugMsg("fileLabel: %v", fileLabel)
	// userlib.DebugMsg("Cabinet: %v", fc.Cabinet)
	//!
	_, exists := fc.Cabinet[fileLabel]
	if !exists {
		return nil, Error("File with given filename does not exist.")
	} else {
		//Get file's structs
		_, fm, err := GetFileStructs(filename, userdata, &fc)
		if err != nil {
			return nil, err
		}

		if !fm.HasAppends {
			//no file appends, just resturn the file data from the first FileNode!
			var file FileNode
			err = GetFileNode(fm.LastFileNodeLoc, fm.FileKey, &file)
			if err != nil {
				return nil, err
			}
			return file.FileData, nil
		} else {
			//file has appends, so we gatta build the file
			dataBytes = make([]byte, fm.TotalByteSize)
			currNode := fm.LastFileNodeLoc
			for !reflect.DeepEqual(currNode, uuid.Nil) {
				var currFile FileNode
				err = GetFileNode(currNode, fm.FileKey, &currFile)
				if err != nil {
					return nil, err
				}

				dstIndex := fm.TotalByteSize - currFile.DataSize
				copy(dataBytes[dstIndex:], currFile.FileData)
				fm.TotalByteSize -= currFile.DataSize

				currNode = currFile.Prev
			}
			return dataBytes, nil
		}
	}
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (accessToken uuid.UUID, err error) {
	//Open user's FileCabinet
	var fc FileCabinet
	err = GetFileCabinet(userdata, &fc)
	if err != nil {
		return uuid.Nil, err
	}

	//Find file
	fileLabel, err := fc.getFileLabel(filename, userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	_, exists := fc.Cabinet[fileLabel]
	if !exists {
		return uuid.Nil, Error("File with given filename does not exist.")
	}
	//Get file's structs
	fb, _, err := GetFileStructs(filename, userdata, &fc)
	if err != nil {
		return uuid.Nil, err
	}

	//get recipient's PKEKey
	recipientPKEKey, ok := userlib.KeystoreGet(recipient + "PKE")
	if !ok {
		return uuid.Nil, Error("Failed to find recipient's PKEKey on Keystore.")
	}

	//Create recipient's AuthUser struct
	var au AuthUser
	accessToken = uuid.New()
	au.AccessToken = accessToken

	if fb.SharedToMe {
		//this is not my file, I will pass on the SharedFile struct
		au.SFKey = fb.SFKey
		au.SFLocation = fb.SFLocation
	} else {
		//this is my file, I will create a new SharedFile struct
		au.SFLocation = uuid.New()
		au.SFKey = userlib.RandomBytes(16)
	}

	//Update user's file's blob
	fb.AuthUsers[recipient] = au
	err = fb.StoreFileBlob(filename, userdata, &fc)
	if err != nil {
		return uuid.Nil, err
	}

	//Create ShareInvitation and marshall
	var si ShareInvitation
	si.SFKey = au.SFKey
	si.SFLocation = au.SFLocation
	siJsonData, err := json.Marshal(si)
	if err != nil {
		return uuid.Nil, err
	}

	//Encrypt and Sign ShareInvitation
	//RSA encryption of ShareInvitation
	ciphertext, err := userlib.PKEEnc(recipientPKEKey, siJsonData)
	if err != nil {
		return uuid.Nil, err
	}

	//Digital Signature
	signature, err := userlib.DSSign(userdata.SignKey, ciphertext)
	if err != nil {
		return uuid.Nil, err
	}

	//Concatenate ciphertext with signature
	ctLen, signLen := len(ciphertext), len(signature)
	signedCiphertext := make([]byte, (ctLen + signLen))
	copy(signedCiphertext[:ctLen], ciphertext)
	copy(signedCiphertext[ctLen:], signature)

	//Save ShareInvitation on Datastore using Accesss Token as the location
	userlib.DatastoreSet(accessToken, signedCiphertext)

	//Create ShareFile Struct and Store on Datastore
	var sf SharedFile
	sf.FMKey = fb.FMKey
	sf.FMLocation = fb.FMLocation
	err = sf.StoreSharedFile(&au)
	if err != nil {
		return uuid.Nil, err
	}

	return accessToken, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string, accessToken uuid.UUID) error {
	//Open user's FileCabinet
	var fc FileCabinet
	err := GetFileCabinet(userdata, &fc)
	if err != nil {
		return err
	}

	//Find file
	fileLabel, err := fc.getFileLabel(filename, userdata.Username)
	if err != nil {
		return err
	}
	_, exists := fc.Cabinet[fileLabel]
	if exists {
		return Error("A file with given filename already exist, please choose a different filename.")
	}

	//Get ShareInvitation form Datastore
	signedCiphertext, ok := userlib.DatastoreGet(accessToken)
	//!Debugging
	userlib.DebugMsg("LEN of signed ciphertext (should be 256?): %v", len(signedCiphertext))
	//!
	if !ok {
		return Error("Failed to get share invitation from Datastore.")
	}

	//Verify
	senderDSVKey, ok := userlib.KeystoreGet(sender + "DS")
	if !ok {
		return Error("Failed to get sender's DSVerifyKey from Keystore.")
	}
	ciphertext := make([]byte, 256)
	signature := make([]byte, 256)
	copy(ciphertext, signedCiphertext[:256])
	copy(signature, signedCiphertext[256:])
	err = userlib.DSVerify(senderDSVKey, ciphertext, signature)
	if err != nil {
		return Error("Could not verify share invitation.")
	}

	//RSA Decryption
	plaintext, err := userlib.PKEDec(userdata.DecKey, ciphertext)
	if err != nil {
		return Error("Could not decrypt share invitation.")
	}

	//Unmarshall share invitation
	var si ShareInvitation
	err = json.Unmarshal(plaintext, &si)
	if err != nil {
		return err
	}

	//Open up the SharedFile struct and create a file blob for file
	var sf SharedFile
	err = sf.GetSharedFile(si.SFLocation, si.SFKey)
	if err != nil {
		return err
	}
	var fb FileBlob
	fb.FMKey = sf.FMKey
	fb.FMLocation = sf.FMLocation
	fb.AuthUsers = make(map[string]AuthUser)
	fb.SFKey = si.SFKey
	fb.SFLocation = si.SFLocation
	fb.SharedToMe = true

	//Update File Cabinet and store file cabinet and file blob
	fc.Cabinet[fileLabel] = uuid.New()
	err = fc.StoreFileCabinet(userdata)
	if err != nil {
		return err
	}
	err = fb.StoreFileBlob(filename, userdata, &fc)
	if err != nil {
		return err
	}

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	//Open user's FileCabinet
	var fc FileCabinet
	err = GetFileCabinet(userdata, &fc)
	if err != nil {
		return err
	}

	//Find file
	fileLabel, err := fc.getFileLabel(filename, userdata.Username)
	if err != nil {
		return err
	}
	_, exists := fc.Cabinet[fileLabel]
	if !exists {
		return Error("File with given filename does not exist.")
	}

	//Get file's structs
	fb, fm, err := GetFileStructs(filename, userdata, &fc)
	if err != nil {
		return err
	}

	//!Debugging
	userlib.DebugMsg("FB: %v", fb)
	userlib.DebugMsg("FM: %v", fm)
	//!

	//Verify owner of file
	if fb.SharedToMe {
		return Error("Can't revoke access from file that user does not own.")
	}

	//Delete targetUser's share invitation and remove user from authenticated user's
	user, exists := fb.AuthUsers[targetUsername]
	if !exists {
		return Error("Target user is not listed as a shared user.")
	}
	userlib.DatastoreDelete(user.AccessToken)
	delete(fb.AuthUsers, targetUsername)

	//Re-encrypt file nodes, and store back to Datastore
	oldKey := fm.FileKey
	newKey := userlib.RandomBytes(16)
	currNode := fm.LastFileNodeLoc
	for !reflect.DeepEqual(currNode, uuid.Nil) {
		var currFile FileNode
		err = GetFileNode(currNode, fm.FileKey, &currFile)
		if err != nil {
			return err
		}

		fm.FileKey = newKey
		err = currFile.StoreFileNode(currNode, &fm)
		if err != nil {
			return err
		}
		fm.FileKey = oldKey

		currNode = currFile.Prev
	}
	fm.FileKey = newKey

	//Change file manager's key, re-encrypt file manager, and store back to Datastore
	fb.FMKey = userlib.RandomBytes(16)
	err = fm.StoreFileManager(&fb)
	if err != nil {
		return err
	}

	//Update authenticated user's access
	for _, au := range fb.AuthUsers {
		var sf SharedFile
		err = sf.GetSharedFile(au.SFLocation, au.SFKey)
		if err != nil {
			return err
		}
		sf.FMKey = fb.FMKey
		sf.StoreSharedFile(&au)
	}

	//Update file blob on Datastore
	err = fb.StoreFileBlob(filename, userdata, &fc)
	if err != nil {
		return err
	}

	return nil
}

/*
********************************************
**             My structures              **
********************************************
 */

// User is the structure definition for a user record.
type User struct {
	Username   string
	FCLocation userlib.UUID
	Key        []byte
	DecKey     userlib.PKEDecKey
	SignKey    userlib.DSSignKey
}

// FileCabinet is the structure definition for a map to file blob locations on the Datastore.
type FileCabinet struct {
	Cabinet map[string]userlib.UUID
}

// FileBlob is the structure definition for a record of who the file has been shared with, and the
// location to the file manager; if this file does not belong to user, then info for the SharedFile
// struct is also saved in here.
type FileBlob struct {
	FMLocation userlib.UUID
	FMKey      []byte //parent key for FileManager
	AuthUsers  map[string]AuthUser
	SFLocation userlib.UUID
	SFKey      []byte //parent key for SharedFile
	SharedToMe bool
}

// FileManager is the structure definition for holding the location to the first and last FileNode
// in a singly-linked list which describes the file data.
type FileManager struct {
	TotalByteSize   int
	FileKey         []byte
	LastFileNodeLoc userlib.UUID
	HasAppends      bool
}

// FileNode is the structure definition for holding a piece of the file data as well as the info
// for the next FileNode; all the nodes together builds the whole file.
type FileNode struct {
	FileData []byte
	DataSize int
	Prev     userlib.UUID
}

// SharedFile is the structure definition for holding info to a file's FileManager.
// Both the user who shared and the user who is being share to have access to this for a file.
type SharedFile struct {
	FMLocation userlib.UUID
	FMKey      []byte
}

// AuthUser is the structure definition for holding an authenticated user's SharedStruct.
type AuthUser struct {
	SFLocation  userlib.UUID
	SFKey       []byte //parent key for SharedFile
	AccessToken userlib.UUID
}

// ShareInvitation is the structure definition for a share invition, which holds the info to a
// SharedFile struct.
type ShareInvitation struct {
	SFLocation userlib.UUID
	SFKey      []byte //parent key for SharedFile
}

/*
********************************************
**          My Helper Functions           **
********************************************
**/

/*
Creates errors with the message passed into it.

	@param:		msg - error message

	@return:		err - error
*/
func Error(msg string) (err error) {
	return errors.New(strings.ToTitle(msg))
}

/*
Creates an encryption key for Symmetric RSA Encyryption and a mac key for HMAC from one parent key.

	@param:		parentKey - 16 byte parent key

	@return:		ek - 16 byte encryption key
	@return:		mk - 16 byte mac key
	@return:		err - error
*/
func getSymKeys(parentKey []byte) (ek []byte, mk []byte, err error) {
	//!Debugging
	userlib.DebugMsg("Length of parent key: %v", len(parentKey))
	//!
	//Verify parameters
	if len(parentKey) != 16 {
		return nil, nil, Error("Parent Key must have a length of 16.")
	}

	//Create Encryption Key
	ek, err = userlib.HashKDF(parentKey, []byte("encryption"))
	if err != nil {
		return nil, nil, err
	}
	ek = ek[:16]

	//Create Mac Key
	mk, err = userlib.HashKDF(parentKey, []byte("mac"))
	if err != nil {
		return nil, nil, err
	}
	mk = mk[:16]

	return
}

/*
Takes a username and password and creates a parent key that is used to create an encryption key for Symmetric RSA Encyryption and a mac key for HMAC.

	@param:		username - users username
	@param:		pw - users password

	@return:		ek - 16 byte encryption key
	@return:		mk - 16 byte mac key
	@return:		err - error
*/
func getAuthParentKey(username string, pw string) (parentKey []byte, err error) {
	//Verify parameters
	if len(username) < 1 || len(pw) < 1 {
		return nil, Error("Username and password cannot be empty.")
	}

	//Slow Hash the password with salt
	parentKey = userlib.Argon2Key([]byte(pw), []byte(username), 16)

	return
}

/*
Adds necessary padding to message for AES-CBC mode encryption, then encrypts the message with the provided encryption key and an IV that is generated within this function.

	@param:		plaintext - the plaintext to be encrypted
	@param:		ek - a 16 byte encryption key

	@return:		ciphertextr - the encrypted plaintext
	@return:		err - error
*/
func getEncrypted(plaintext []byte, ek []byte) (ciphertext []byte, err error) {
	//!Debugging
	// userlib.DebugMsg("Plaintext: %v", plaintext)
	//!
	//Verify parameters
	if len(plaintext) < 1 {
		return nil, Error("Plaintext cannot be empty")
	}
	if len(ek) != userlib.AESKeySizeBytes {
		return nil, Error("Encryption key must have a length of 16.")
	}

	//Generate Random IV needed for the AES-CBC encryption
	iv := userlib.RandomBytes(16)

	//Pad the plaintext
	padSize := userlib.AESBlockSizeBytes - (len(plaintext) % userlib.AESBlockSizeBytes)
	if padSize == 0 {
		padSize = userlib.AESBlockSizeBytes
	}
	//!Debugging
	// userlib.DebugMsg("padSize: %v", padSize)
	//!
	pad := make([]byte, padSize)
	for i := 0; i < padSize; i++ {
		pad[i] = byte(padSize)
	}
	//!Debugging
	// userlib.DebugMsg("pad: %v", pad)
	//!
	ptPadded := make([]byte, len(pad)+len(plaintext))
	copy(ptPadded, plaintext)
	//!Debugging
	// userlib.DebugMsg("Padded Plaintext before adding pad: %v", ptPadded)
	//!
	copy(ptPadded[len(plaintext):], pad)
	//!Debugging
	// userlib.DebugMsg("Padded Plaintext after adding pad: %v", ptPadded)
	//!

	//AES-CBC mode Symmetric Encryption
	ciphertext = userlib.SymEnc(ek, iv, ptPadded)
	//!Debugging
	// userlib.DebugMsg("ciphertext: %v", ciphertext)
	//!

	return
}

/*
Produces a ta
a tag is produced for the ciphertext using HMAC, which is then concatenated to the ciphertext and returned.

	@param:		plaintext - the message to be encrypted
	@param:		ek - a 16 byte encryption key
	@param:		mk - a 16 byte mac key

	@return:		result - the encrypted message concatented with its MAC tag
	@return:		err - error
*/
func getMACed(ciphertext []byte, mk []byte) (result []byte, err error) {
	//Verify parameters
	if len(ciphertext) < 1 {
		return nil, Error("Ciphertext cannot be empty")
	}
	if len(mk) != userlib.AESKeySizeBytes {
		return nil, Error("Mac key must have a length of 16.")
	}

	tag, err := userlib.HMACEval(mk, ciphertext)
	if err != nil {
		return nil, err
	}
	//!Debugging
	// userlib.DebugMsg("MAC tag: %v", tag)
	//!

	//Attatch tag to end of ciphertext
	result = make([]byte, len(ciphertext)+len(tag))
	copy(result, ciphertext)
	//!Debugging
	// userlib.DebugMsg("result before adding tag: %v", result)
	//!
	copy(result[len(ciphertext):], tag)
	//!Debugging
	// userlib.DebugMsg("result after adding tag: %v", result)
	//!

	return
}

/*
Adds necessary padding to message for AES-CBC mode encryption, then encrypts the message with the provided encryption key and an IV that is generated within this function.  Then a tag is produced for the ciphertext using HMAC, which is then concatenated to the ciphertext and returned.

	@param:		plaintext - the message to be encrypted
	@param:		ek - a 16 byte encryption key
	@param:		mk - a 16 byte mac key

	@return:		result - the encrypted message concatented with its MAC tag
	@return:		err - error
*/
func encryptThenMac(plaintext []byte, parentKey []byte) (result []byte, err error) {
	//Get symmetric keys
	ek, mk, err := getSymKeys(parentKey)
	if err != nil {
		return nil, err
	}

	//encrypt
	ciphertext, err := getEncrypted(plaintext, ek)
	if err != nil {
		return nil, err
	}

	//mac
	result, err = getMACed(ciphertext, mk)
	if err != nil {
		return nil, err
	}

	return
}

/*
Verifies that the tag at the end of the data matches the data itself.

	@param:		data - the data to be verified
	@param:		mk - a 16 byte mac key

	@return:		verifiedData - the verified data without the tag at the end
	@return:		err - error
*/
func getVerified(data []byte, mk []byte) (verifiedData []byte, err error) {
	//Verify parameters
	if len(data) < 80 { // (iv = 16) + (tag = 64)
		return nil, Error("Data cannot be less than 64 bytes [must have the tag attatched].")
	}
	if len(mk) != userlib.AESKeySizeBytes {
		return nil, Error("Mac key must have a length of 16.")
	}

	//Detatch tag from data to get the ciphertext
	tag := data[(len(data) - 64):]
	ciphertext := data[:(len(data) - 64)]
	//! Debugging
	// userlib.DebugMsg("tag: %v", tag)
	// userlib.DebugMsg("LEN(DATA): %v", len(data))
	// userlib.DebugMsg("LEN(TAG): %v", len(tag))
	// userlib.DebugMsg("LEN(CIPHERTEXT): %v", len(ciphertext))
	//!

	//Re-calculate the tag
	calculatedTag, err := userlib.HMACEval(mk, ciphertext)
	if err != nil {
		return nil, err
	}
	//! Debugging
	// userlib.DebugMsg("calculated tag: %v", calculatedTag)
	//!

	//Compare the tags to verify data has not been tampered with
	if !userlib.HMACEqual(tag, calculatedTag) {
		return nil, Error("Data's integrity has been compromised.")
	} else {
		return ciphertext, nil
	}
}

/*
Decrypts data that was encrypted using AES-CBC mode encryption.

	@param:		data - the data to be decrypted
	@param:		ek - a 16 byte encryption key

	@return:		plaintext - the decrypted data
	@return:		err - error
*/
func getDecrypted(ciphertext []byte, ek []byte) (plaintext []byte, err error) {
	//Verify parameters
	if len(ciphertext) < 1 {
		return nil, Error("Ciphertext cannot be empty.")
	}
	if len(ek) != userlib.AESKeySizeBytes {
		return nil, Error("Encryption key must have a length of 16.")
	}
	if len(ciphertext)%userlib.AESBlockSizeBytes != 0 {
		return nil, Error("Ciphertext must be in blocks of size 16.")
	}

	//Decrypt
	paddedPlaintext := userlib.SymDec(ek, ciphertext)

	//Un-pad
	padSize := paddedPlaintext[len(paddedPlaintext)-1]
	plaintextSize := len(paddedPlaintext) - int(padSize)
	plaintext = paddedPlaintext[:plaintextSize]

	return
}

/*
Verifies that the tag at the end of the data matches the data itself, then decrypts the data.

	@param:		data - the message to be verified and decrypted
	@param:		parentKey - a 16 byte parentKey key

	@return:		plaintext - the decrypted message
	@return:		err - error
*/
func verifyThendecrypt(data []byte, parentKey []byte) (plaintext []byte, err error) {
	//Get symmetric keys
	ek, mk, err := getSymKeys(parentKey)
	if err != nil {
		return nil, err
	}

	//verify
	ciphertext, err := getVerified(data, mk)
	//!Debugging
	userlib.DebugMsg("GETVERIFIED ERROR: %v", err)
	//!
	if err != nil {
		return nil, err
	}

	//decrypt
	plaintext, err = getDecrypted(ciphertext, ek)
	if err != nil {
		return nil, err
	}
	return
}

/*
Gets a users iles fileLabel for the Cabinet map in the FileCabinet struct.

	@param:		filename - the name of the file
	@param:		username - the users username

	@return:		fileLabel - aka the files key value in the cabinet map
	@return:		err - error
*/
func (fc FileCabinet) getFileLabel(filename string, username string) (fileLabel string, err error) {
	//Verify parameters
	if len(username) < 1 {
		return fileLabel, Error("Username cannot be empty or nil.")
	}
	fileLabel = hex.EncodeToString(userlib.Hash([]byte(username + filename)))
	return fileLabel, nil
}

/*
Gets json data from the Datastore.

	@param:		location - the location of json data on Datastore
	@param:		parentKey - a 16 byte parent key

	@return:		jsonData - json data that describes an object
	@return:		err - error
*/
func GetJsonData(location userlib.UUID, parentKey []byte) (jsonData []byte, err error) {
	//Verify parameters
	if location == uuid.Nil {
		return nil, Error("Location cannot be nil.")
	}
	if parentKey == nil {
		return nil, Error("ParentKey cannot be nil.")
	}

	//Get obj from Datastore
	cryptedData, ok := userlib.DatastoreGet(location)
	if !ok {
		return nil, Error("No Datastore entry with given location.")
	}

	//Verify then Decrypt crypted data
	jsonData, err = verifyThendecrypt(cryptedData, parentKey)
	if err != nil {
		return nil, err
	}

	return
}

/*
Gets FileCabinet from the Datastore for a user.

	@param:		user - pointer to the Users struct
	@param:		fileCabinetptr - pointer to an empty FileCabinet struct

	@return:		err - error
*/
func GetFileCabinet(user *User, fileCabinetptr *FileCabinet) (err error) {
	//Verify parameters
	if user == nil {
		return Error("User cannot be nil.")
	}
	if fileCabinetptr == nil {
		return Error("FileCabinet cannot be nil.")
	}

	//Get jsaon data
	location, parentKey := user.FCLocation, user.Key
	jsonData, err := GetJsonData(location, parentKey)
	if err != nil {
		return err
	}

	//Unmarshall json data
	err = json.Unmarshal(jsonData, fileCabinetptr)
	if err != nil {
		return err
	}

	return

}

/*
Gets FileBlob from the Datastore for a file.

	@param:		filename - the filename
	@param:		user - pointer to the Users struct
	@param:		fileBlob - pointer to a empty FileBlob struct

	@return:		err - error
*/
func (fileCabinet *FileCabinet) GetFileBlob(filename string, user *User, fileBlob *FileBlob) (err error) {
	//Verify parameters
	if user == nil {
		return Error("User cannot be nil.")
	}
	if fileBlob == nil {
		return Error("FileBlob cannot be nil.")
	}

	//Get blob's jsaon data
	fileLabel := hex.EncodeToString(userlib.Hash([]byte(user.Username + filename)))
	location, parentKey := fileCabinet.Cabinet[fileLabel], user.Key
	jsonData, err := GetJsonData(location, parentKey)
	if err != nil {
		return err
	}

	//Unmarshall blob's json data
	err = json.Unmarshal(jsonData, fileBlob)
	if err != nil {
		return err
	}

	return

}

/*
Gets FileManager from the Datastore for a file.

	@param:		user - pointer to the Users struct
	@param:		fileManager - pointer to a empty FileManager struct

	@return:		err - error
*/
func (fileBlob *FileBlob) GetFileManager(user *User, fileManager *FileManager) (err error) {
	//Verify parameters
	if user == nil {
		return Error("User cannot be nil.")
	}
	if fileManager == nil {
		return Error("FileManager cannot be nil.")
	}

	//Get manager's json data
	location, parentKey := fileBlob.FMLocation, fileBlob.FMKey
	jsonData, err := GetJsonData(location, parentKey)
	if err != nil {
		return err
	}

	//Unmarshall manager's json data
	err = json.Unmarshal(jsonData, fileManager)
	if err != nil {
		return err
	}

	return
}

/*
Gets SharedFile from the Datastore for a file share invitation.

	@param:		location - location of SharedFile struct on Datastore
	@param: 	parentKey - a 16 byte parent key for symmetric encryption

	@return:		err - error
*/
func (sharedFile *SharedFile) GetSharedFile(location userlib.UUID, parentKey []byte) (err error) {
	//Verify parameters
	if sharedFile == nil {
		return Error("SharedFile cannot be nil.")
	}

	//Get sharedFil's json data
	jsonData, err := GetJsonData(location, parentKey)
	if err != nil {
		return err
	}

	//Unmarshall sharedFile's json data
	err = json.Unmarshal(jsonData, sharedFile)
	if err != nil {
		return err
	}

	return
}

/*
Gets FileNode from the Datastore for a file.

	@param:		location - fileNodes location on the Datastore
	@param:		parentKey - fileNodes parent key for symmetric encryption
	@param:		fileNode - pointer to a empty FileNode struct

	@return:		err - error
*/
func GetFileNode(location userlib.UUID, parentKey []byte, fileNode *FileNode) (err error) {
	//Verify parameters
	if fileNode == nil {
		return Error("FileNode cannot be nil.")
	}

	//Get node's json data
	jsonData, err := GetJsonData(location, parentKey)
	if err != nil {
		return err
	}

	//Unmarshall node's json data
	err = json.Unmarshal(jsonData, fileNode)

	return
}

/*
Returns a files strucs from the Datastore. This function assumes that the file does exist in the users file cabinet.

	@param:		filename - name of file
	@param:		user - pointer to User struct
	@param:		fc - pointer to users FileCabinet

	@return:		fb - users Fileblob for file
	@return:		fm - files FileManager
	@return:		err - error
*/
func GetFileStructs(filename string, user *User, fc *FileCabinet) (fb FileBlob, fm FileManager, err error) {
	//Verify parameters
	if user == nil {
		return fb, fm, Error("User cannot be nil.")
	}
	if fc == nil {
		return fb, fm, Error("FileCabinet cannot be nil.")
	}

	//Get FileBlob
	err = fc.GetFileBlob(filename, user, &fb)
	if err != nil {
		return fb, fm, err
	}

	//Get file's FileManager
	err = fb.GetFileManager(user, &fm)
	if err != nil { //data has been compromised
		if fb.SharedToMe {
			//this file was shared to this user
			//check for updated FMkey in shared file struct
			var sf SharedFile
			err = sf.GetSharedFile(fb.SFLocation, fb.SFKey)
			if err != nil {
				return fb, fm, err
			}
			fb.FMKey = sf.FMKey
			//attempt to get file's FileManager again
			err = fb.GetFileManager(user, &fm)
			if err != nil {
				//this user no longer has access to the file and its FileManager or something
				// went wrong ):
				return fb, fm, err
			}
		} else {
			//this file belongs to the user, and something went wrong getting their blob
			return fb, fm, err
		}
	}

	return fb, fm, nil
}

/*
Encrypts and stores json data onto the Datastore.

	@param:		jsonData - json data to be ecypted and stored
	@param:		location - the location for json data on Datastore
	@param:		parentKey - a 16 byte parent key

	@return:		err - error
*/
func StoreJsonData(jsonData []byte, location userlib.UUID, parentKey []byte) (err error) {
	//Verify parameters
	if jsonData == nil || reflect.DeepEqual(jsonData, []byte("")) {
		return Error("JsonData cannot be empty or nil.")
	}
	if location == uuid.Nil {
		return Error("Location cannot nil.")
	}

	//Encrypt then Mac
	ciphertext, err := encryptThenMac(jsonData, parentKey)

	//Store onto Datastore
	userlib.DatastoreSet(location, ciphertext)

	return nil
}

/*
Encrypts and stores a users FileCabinet a onto the Datastore.

	@param:		user - pointer to User struct

	@return:		err - error
*/
func (fc *FileCabinet) StoreFileCabinet(user *User) (err error) {
	//Verify paramter
	if user == nil {
		return Error("User cannot be nil.")
	}

	//Marshal FileCabinet
	jsonData, err := json.Marshal(fc)
	if err != nil {
		return err
	}

	//Store FileCabinet json data
	err = StoreJsonData(jsonData, user.FCLocation, user.Key)
	if err != nil {
		return err
	}

	return nil
}

/*
Encrypts and stores a files FileCabinet a onto the Datastore.

	@param: 	filename - name of blobs file
	@param:		user - pointer to User struct
	@param: 	fc - pointer to File Cabinet struct

	@return:		err - error
*/
func (fb *FileBlob) StoreFileBlob(filename string, user *User, fc *FileCabinet) (err error) {
	//Verify paramter
	if user == nil {
		return Error("User cannot be nil.")
	}
	if fc == nil {
		return Error("FileCabinet cannot be nil.")
	}

	//Marshal FileBlob
	jsonData, err := json.Marshal(fb)
	if err != nil {
		return err
	}

	//Store FileBlob json data
	fileLabel := hex.EncodeToString(userlib.Hash([]byte(user.Username + filename)))
	err = StoreJsonData(jsonData, fc.Cabinet[fileLabel], user.Key)
	if err != nil {
		return err
	}

	return nil
}

/*
Encrypts and stores a files FileManager onto the Datastore.

	@param: 	fb - pointer to files FileBlob struct

	@return:		err - error
*/
func (fm *FileManager) StoreFileManager(fb *FileBlob) (err error) {
	//Verify parameters
	if fb == nil {
		return Error("FileBlob cannot be nil.")
	}

	//Marshal FileCabinet
	jsonData, err := json.Marshal(fm)
	if err != nil {
		return err
	}

	//Store FileCabinet json data
	err = StoreJsonData(jsonData, fb.FMLocation, fb.FMKey)
	if err != nil {
		return err
	}

	return nil
}

/*
Encrypts and stores a FileNode onto the Datastore.

	@param: 	location - location to store node on Datastore
	@param: 	fm - pointer to nodes FileManager struct

	@return:		err - error
*/
func (node *FileNode) StoreFileNode(location userlib.UUID, fm *FileManager) (err error) {
	//Verify parameters
	if location == uuid.Nil {
		return Error("FileManager cannot be nil.")
	}
	if fm == nil {
		return Error("FileManager cannot be nil.")
	}

	//Marshal FileCabinet
	jsonData, err := json.Marshal(node)
	if err != nil {
		return err
	}

	//Store FileCabinet json data
	err = StoreJsonData(jsonData, location, fm.FileKey)
	if err != nil {
		return err
	}

	return nil
}

/*
Encrypts and stores a SharedFile struct onto the Datastore.

	@param: 	si - pointer to sfs ShareInvitation struct

	@return:		err - error
*/
func (sf *SharedFile) StoreSharedFile(au *AuthUser) (err error) {
	//Verify parameters
	if au == nil {
		return Error("FileManager cannot be nil.")
	}

	//Marshal FileCabinet
	jsonData, err := json.Marshal(sf)
	if err != nil {
		return err
	}

	//Store FileCabinet json data
	err = StoreJsonData(jsonData, au.SFLocation, au.SFKey)
	if err != nil {
		return err
	}

	return nil
}
