package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"
	//"go/types"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	. "github.com/google/uuid"

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
	f := New()
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
	var g UUID
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

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string

	MasterKey []byte //holds master key

	//Struct Location Key, location to store and retrive this struct
	StructLocation []byte //HashKDF()

	//Struct uuid, used for struct authentication
	UserUUID UUID

	//Public Encryption Key pair, probably used for send and receive files.
	PrivateDecKey userlib.PKEDecKey //PKEKeyGen() userlib.PKEKeyGen()

	//Private Signature used to sign sent message
	PrivateSignKey userlib.DSSignKey //DSKeyGen() userlib.DSKeyGen()

	//Use RandomBytes generate symmetric key, HMAC key, file key
	EncryptKey []byte
	EncryptIV  []byte
	HMACKey    []byte //userlib.RandomBytes(mkey.length)

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)

	//Key and HMAC used to encrypt and verify Accessible List
	AccessibleUUID       UUID   //uuid of accessible list
	AccessibleEncryptKey []byte //Key used to encrypt Accessible List
	AccessibleIV         []byte //IV used to encrypt Accessible List
	AccessibleHMAC       []byte //HMAC used to verify Accessible List
}

type Pair struct {
	FileUUID UUID
	SymKey   []byte
	IV       []byte
	HMAC     []byte
}

type SharingPair struct {
	EncMsg    []byte
	Signature []byte
}

type AccessibleList struct {
	Owned  map[string]Pair
	Shared map[string]Pair
}

type FileHeader struct {
	FileHeaderUUID UUID   //UUID of this FileHeader Object
	EncryptKey     []byte //used for encrypting the file
	EncryptIV      []byte //used for encrypting the file
	HMACKey        []byte //user for verifying the file
	NodeEncryptKey []byte //used for encrypting FileNode Objects
	NodeEncryptIV  []byte //used for encrypting FileNode Objects
	NodeHMACKey    []byte //used for verifying FileNode objects
	HeadUUID       UUID   //UUID of the Head FileNode
	TailUUID       UUID   // UUID of the Tail FileNode
}

type FileNode struct {
	Data         []byte //symmetrically encrypted data
	FileNodeUUID UUID   // UUID of this specific filenode
	NextUUID     UUID   //UUID of next file node
}

type Guardian struct {
	GuardianUUID   UUID            //UUID of this Gurdian object, used in accessible file of user
	FileHeaderUUID UUID            //UUID of the related FileHeader Object
	EncryptKey     []byte          //used for encrypting the FileHeader
	EncryptIV      []byte          //used encrypting the FileHeader
	HMACKey        []byte          // Used to verify the FileHeader
	Owner          string          //Only Owner can perform sharing
	AllowedUser    map[string]bool //Users that are allowed to access this file
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	//var accessiblelist AccessibleList
	userdataptr = &userdata

	userdata.Username = username

	//checks if username already exists; if not, generate keys
	_, used := userlib.KeystoreGet(username)
	if used {
		return nil, errors.New("username duplicated")
	} else {
		//master key (pbkd)
		masterKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize))
		userdata.MasterKey = masterKey

		//location key (hkdf) for storing the User Struct in Datastore
		lk, _ := userlib.HashKDF(masterKey, []byte("StructLocation"))
		userdata.StructLocation = lk

		//PKE key pair, generate private decryption key and public encryption key
		ek, dk, _ := userlib.PKEKeyGen()
		//convert username to key
		userlib.KeystoreSet(username, ek)
		userdata.PrivateDecKey = dk

		//digital signature key pair, generate private signature key and public signature key
		privateSign, publicSign, _ := userlib.DSKeyGen()
		userlib.KeystoreSet(username+"vfy", publicSign)
		userdata.PrivateSignKey = privateSign

		//HMAC key
		//hmac, _ := userlib.HashKDF(masterKey, []byte("StructHMAC"))
		hmac := userlib.Argon2Key([]byte(password), []byte(username+"HMAC"), uint32(userlib.AESBlockSize))
		userdata.HMACKey = hmac

		//UserStruct Location Key
		lockey, _ := userlib.HashKDF(masterKey, []byte("Location"))
		userdata.StructLocation = lockey

		//IV, encrypt key, and HMAC key related to accessibleList
		auuid := New()
		userdata.AccessibleUUID = auuid
		accessibleEncryptKey := userlib.RandomBytes(userlib.AESKeySize)
		userdata.AccessibleEncryptKey = accessibleEncryptKey
		accessibleIV := userlib.RandomBytes(userlib.AESBlockSize)
		userdata.AccessibleIV = accessibleIV
		accessibleHMAC := userlib.RandomBytes(userlib.AESKeySize)
		userdata.AccessibleHMAC = accessibleHMAC
		var accessible AccessibleList
		encryptAndStore(accessible, userdata.AccessibleIV, userdata.AccessibleEncryptKey, userdata.AccessibleHMAC, auuid)

		//UserStruct UUID
		suuid := bytesToUUID(masterKey)
		userdata.UserUUID = suuid

		//marshal to json
		//userdataMarshaled, _ := json.Marshal(userdata)
		//encrypt userdata (using symmetric encryption) and derive key and IV using HKDF
		userEncryptKey, _ := userlib.HashKDF(masterKey, []byte("StructEncryptKey"))
		userEncryptIV, _ := userlib.HashKDF(masterKey, []byte("StructEncryptIV"))
		//userdataEncrypted := userlib.SymEnc(userEncryptKey[:userlib.AESKeySize], userEncryptIV[:userlib.AESKeySize], userdataMarshaled)
		//generate HMAC
		//HMACTag, _ := userlib.HMACEval(userdata.HMACKey[:userlib.AESKeySize], userdataEncrypted)
		//append HMAC tag to the end of the encrypted userdata
		//userdataHMACed := append(userdataEncrypted, HMACTag...)
		//userlib.DatastoreSet(suuid, userdataHMACed)
		encryptAndStore(userdata, userEncryptIV[:userlib.AESBlockSize], userEncryptKey[:userlib.AESKeySize], userdata.HMACKey, suuid)

	}

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//return value from KeyStore
	_, ok := userlib.KeystoreGet(username)
	//check if username can be found in Keystore
	if !ok {
		return nil, errors.New("Invalid user")
	}

	//pbkd to generate key from password and username, see if it's stored in Datastore
	masterKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize))
	userEncryptKey, _ := userlib.HashKDF(masterKey[:16], []byte("StructEncryptKey"))
	sHMACKey := userlib.Argon2Key([]byte(password), []byte(username+"HMAC"), uint32(userlib.AESBlockSize))
	cipher, correctPswd := userlib.DatastoreGet(bytesToUUID(masterKey))
	//check that username + password are valid
	if !correctPswd {
		return nil, errors.New("Incorrect password")
	}
	//check if user data is corrupt
	// correctUserdataHMACed := userlib.DatastoreGet(userdata.UUID)
	//unappend correctUserdataHMACed to get HMAC
	length := len(cipher)
	if length < userlib.AESBlockSize {
		return nil, errors.New(string(length))
	}

	correctUserdataEnc := cipher[:(length - userlib.HashSize)]
	correctHMAC := cipher[(length - userlib.HashSize):]

	tag, _ := userlib.HMACEval(sHMACKey, correctUserdataEnc)
	//return nil , errors.New(strconv.FormatInt(int64(userlib.HashSize), 10))

	//compare HMACs
	if !userlib.HMACEqual(tag, correctHMAC) {
		return nil, errors.New("User data is corrupt")
	}
	//decrypt and unmarshal user struct if correct user credentials and integrity
	decrypted := userlib.SymDec(userEncryptKey[:userlib.AESKeySize], correctUserdataEnc)

	err = json.Unmarshal(decrypted, userdataptr)
	if err != nil {
		userdataptr = nil
		err = errors.New("Json Error")
		return
	}
	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//Check if this filename is used for another file
	cUUID, _ := FromBytes([]byte(filename + userdata.Username)[:16])
	_, err := userlib.DatastoreGet(cUUID) //
	if err == false {
		userdata.overwriteFile(filename, data)
		return
	}

	//Assign UUID to FileHeader and Guardian objects
	var fileHeader FileHeader
	newUUID := New()
	fileHeader.FileHeaderUUID = newUUID
	var guardian Guardian
	newUUID = New()
	guardian.GuardianUUID = newUUID
	guardian.FileHeaderUUID = fileHeader.FileHeaderUUID

	//Assign ownername
	guardian.Owner = userdata.Username
	guardian.AllowedUser[userdata.Username] = true

	//initialize keys and mac for encrypt file header
	fileHeaderEncryptKey := userlib.RandomBytes(userlib.AESKeySize)
	fileHeaderEncryptIV := userlib.RandomBytes(userlib.AESBlockSize)
	guardian.EncryptKey = fileHeaderEncryptKey
	guardian.EncryptIV = fileHeaderEncryptIV
	fileHeaderHMACKey := userlib.RandomBytes(userlib.AESKeySize)
	guardian.HMACKey = fileHeaderHMACKey

	//initialize keys and mac for fileNode
	fileNodeEncryptKey := userlib.RandomBytes(userlib.AESKeySize)
	fileNodeEncryptIV := userlib.RandomBytes(userlib.AESBlockSize)
	fileHeader.NodeEncryptKey = fileNodeEncryptKey
	fileHeader.NodeEncryptIV = fileNodeEncryptIV
	fileNodeHMACKey := userlib.RandomBytes(userlib.AESKeySize)
	fileHeader.NodeHMACKey = fileNodeHMACKey

	//initialize keys and mac for file
	fileEncryptKey := userlib.RandomBytes(userlib.AESKeySize)
	fileEncryptIV := userlib.RandomBytes(userlib.AESBlockSize)
	fileHeader.EncryptKey = fileEncryptKey
	fileHeader.EncryptIV = fileEncryptIV
	fileHMACKey := userlib.RandomBytes(userlib.AESKeySize)
	fileHeader.HMACKey = fileHMACKey

	//Encrypt and authenticate file
	encryptedFile, taggedFile := fileHeader.encryptFileNode(data)
	userdataHMACed := append(encryptedFile, taggedFile...)

	//Create fileNode to store encrypted data
	var fnode FileNode
	fnuuid := New()
	fnode.FileNodeUUID = fnuuid
	fnode.NextUUID = Nil
	fnode.Data = userdataHMACed

	//Set head and tail
	fileHeader.HeadUUID = fnode.FileNodeUUID
	fileHeader.TailUUID = fnode.FileNodeUUID

	//Marshall All objects
	//fileNodeMarshalled, _ := json.Marshal(fnode)

	//encrypt and verify FileNode object
	//encryptedFileNode := userlib.SymEnc(fileHeader.NodeEncryptKey, fileHeader.NodeEncryptIV, fileNodeMarshalled)
	//encryptedFileNodeHMAC, _ := userlib.HMACEval(fileHeader.NodeHMACKey, encryptedFileNode)
	//storeFileNode := append(encryptedFileNode, encryptedFileNodeHMAC...)
	encryptAndStore(fnode, fileHeader.NodeEncryptIV, fileHeader.NodeEncryptKey, fileHeader.NodeHMACKey, fnode.FileNodeUUID)

	encryptAndStore(fileHeader, guardian.EncryptIV, guardian.EncryptKey, guardian.HMACKey, fileHeader.FileHeaderUUID)

	//initialize encryption key and mac for guardian
	guardianSymKey := userlib.RandomBytes(userlib.AESKeySize)
	guardianIV := userlib.RandomBytes(userlib.AESBlockSize)
	guardianHMAC := userlib.RandomBytes(userlib.AESKeySize)
	guardianPair := Pair{guardian.GuardianUUID, guardianSymKey, guardianIV, guardianHMAC}

	encryptAndStore(guardian, guardianIV, guardianSymKey, guardianHMAC, guardian.GuardianUUID)

	//Store all of them into Datastore
	//userlib.DatastoreSet(fnode.FileNodeUUID, storeFileNode)
	//userlib.DatastoreSet(fileHeader.FileHeaderUUID, storeFileHeader)
	//userlib.DatastoreSet(guardian.GuardianUUID, storeGurdian)

	//TODO: add to accessible and owned list
	accessible, accesserr := userdata.getAccessibleList()
	if accesserr != nil {
		return
	}
	accessible.Owned[filename] = guardianPair

	userlib.DatastoreDelete(userdata.AccessibleUUID)
	encryptAndStore(accessible, userdata.AccessibleIV, userdata.AccessibleEncryptKey, userdata.AccessibleHMAC, userdata.AccessibleUUID)

	return
}

func encryptAndStore(i interface{}, iv []byte, key []byte, hmac []byte, muuid UUID) {
	marshalled, _ := json.Marshal(i)
	encrypted := userlib.SymEnc(key, iv, marshalled)
	hmaced, _ := userlib.HMACEval(hmac, encrypted)
	encrypted = append(encrypted, hmaced...)
	userlib.DatastoreSet(muuid, encrypted)
}

func (userdata *User) overwriteFile(filename string, data []byte) {
	return
}

func (fileHeader *FileHeader) encryptFileNode(data []byte) ([]byte, []byte) {
	fileEncrypted := userlib.SymEnc(fileHeader.EncryptKey, fileHeader.EncryptIV, data)
	HMACTag, _ := userlib.HMACEval(fileHeader.HMACKey, data)
	return fileEncrypted, HMACTag
}

//type Guardian struct {
//	UUID           UUID
//	EncryptKey     []byte
//	HMACKey        []byte
//	Owner          string
//	AccessibleUser []string
//}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//retrieve file content
	//compare HMACs to check for integrity
	//decrypt file content
	//update file structure
	//marshal file struct, encrypt, hmac, and store in Datastore
	//TODO: Append to Tail, would be fast given function I defined below
	return
}

func (userdata *User) getAccessibleList() (*AccessibleList, error) {
	accessibleUnDecrypt, err := userlib.DatastoreGet(userdata.AccessibleUUID)
	if err {
		return nil, errors.New("No such file")
	}
	length := len(accessibleUnDecrypt)
	if length <= userlib.HashSize {
		return nil, errors.New("Decryption Failed")
	}
	accessibleHMAC := accessibleUnDecrypt[length-userlib.HashSize:]
	if !userlib.HMACEqual(accessibleHMAC, userdata.AccessibleHMAC) {
		return nil, errors.New("Authentication Failed")
	}
	decryptAccessible := userlib.SymDec(userdata.AccessibleEncryptKey, accessibleUnDecrypt[:length-userlib.HashSize])
	var accessible AccessibleList
	jsonError := json.Unmarshal(decryptAccessible, &accessible)
	if jsonError != nil {
		return nil, errors.New("Decryption Failed")
	}
	return &accessible, nil
}

func (userdata *User) getGuardian(filename string, accessible *AccessibleList) (*Guardian, error) {
	guardianUUID, accesserr := accessible.Owned[filename]
	if !accesserr {
		guardianUUID, accesserr = accessible.Shared[filename]
		if accesserr {
			return nil, errors.New("File not accessible")
		}
	}
	guardianUnDecrypt, datastoreerr := userlib.DatastoreGet(guardianUUID.FileUUID)
	if datastoreerr {
		return nil, errors.New("No such file exists")
	}
	length := len(guardianUnDecrypt)
	if length <= userlib.HashSize {
		return nil, errors.New("Decryption Failed")
	}
	guardianHMAC := userlib.HMACEqual(guardianUnDecrypt[length-userlib.HashSize:], guardianUUID.HMAC)
	if !guardianHMAC {
		return nil, errors.New("Authentication Failed")
	}
	guardianDecrypted := userlib.SymDec(guardianUUID.SymKey, guardianUnDecrypt[:length-userlib.HashSize])
	var guardian Guardian
	jsonerr := json.Unmarshal(guardianDecrypted, &guardian)
	if jsonerr != nil {
		return nil, errors.New("Decryption Failed")
	}
	return &guardian, nil
}

func (userdata *User) getFileHeader(guardian *Guardian) (*FileHeader, error) {
	fhUnDecrypt, fherror := userlib.DatastoreGet(guardian.FileHeaderUUID)
	if !fherror {
		return nil, errors.New("Data Error")
	}
	length := len(fhUnDecrypt)
	if length <= userlib.HashSize {
		return nil, errors.New("Data Error")
	}
	fhhmaced := userlib.HMACEqual(guardian.HMACKey, fhUnDecrypt[length-userlib.HashSize:])
	if !fhhmaced {
		return nil, errors.New("Data Authentication Failed")
	}
	fhDecrypted := userlib.SymDec(guardian.EncryptKey, fhUnDecrypt[:length-userlib.HashSize])
	var fileHeader FileHeader
	jsonerr := json.Unmarshal(fhDecrypted, &fileHeader)
	if jsonerr != nil {
		return nil, errors.New("Data Decryption Error")
	}
	return &fileHeader, nil
}

func (userdata *User) checkAccessibility(filename string) (*FileHeader, error) {
	accessible, err := userdata.getAccessibleList()
	if err != nil {
		return nil, err
	}
	guardian, err := userdata.getGuardian(filename, accessible)
	if err != nil {
		return nil, err
	}
	allowed, allowederr := guardian.AllowedUser[userdata.Username]
	if !allowed || !allowederr {
		return nil, errors.New("Not allowed")
	}
	fileHeader, fherror := userdata.getFileHeader(guardian)
	if fherror != nil {
		return nil, errors.New("Data Error")
	}
	return fileHeader, nil

}
func (fileHeader *FileHeader) decryptFileNode(fnuuid UUID) (*FileNode, error) {
	fn, err := userlib.DatastoreGet(fnuuid)
	if !err {
		return nil, errors.New("Data Error")
	}
	length := len(fn)
	if length < userlib.HashSize {
		return nil, errors.New("Data Errors")
	}
	hmac := userlib.HMACEqual(fileHeader.NodeHMACKey, fn[length-userlib.HashSize:])
	if !hmac {
		return nil, errors.New("Authentication Failed")
	}
	var fnode FileNode
	jsonerr := json.Unmarshal(fn[:length-userlib.HashSize], &fnode)
	if jsonerr != nil {
		return nil, errors.New("Data Error")
	}
	return &fnode, nil
}

func (fileHeader *FileHeader) extractFile(fnode *FileNode) ([]byte, error) {
	//TODO: decrypt data stored on each node
	length := len(fnode.Data)
	if length < userlib.HashSize {
		return nil, errors.New("Data Error")
	}
	hmac := userlib.HMACEqual(fileHeader.HMACKey, fnode.Data[length-userlib.HashSize:])
	if !hmac {
		return nil, errors.New("Authentication Failed")
	}
	decrypted := userlib.SymDec(fileHeader.EncryptKey, fnode.Data[:length-userlib.HashSize])
	return decrypted, nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//UUID, _ := FromBytes([]byte(filename + userdata.Username)[:16])
	//packaged_data, ok := userlib.DatastoreGet(UUID)
	//if !ok {
	//	return nil, errors.New(strings.ToTitle("File not found!"))
	//}
	//json.Unmarshal(packaged_data, &data)
	//return data, nil
	//End of toy implementation
	fileHeader, err := userdata.checkAccessibility(filename)
	if err != nil {
		data = nil
		return
	}
	//fileNode, err := fileHeader.decryptFileNode(fileHeader.HeadUUID)
	//if err != nil {
	//	data = nil
	//	return
	//}
	data = []byte("")
	currUUID := fileHeader.HeadUUID
	for currUUID != Nil {
		currNode, cerr := fileHeader.decryptFileNode(currUUID)
		if cerr != nil {
			data = nil
			err = errors.New("Data Error")
			return
		}
		d, derr := fileHeader.extractFile(currNode)
		if derr != nil {
			data = nil
			err = errors.New("Decryption Failed")
		}
		data = append(data, d...)
		currUUID = currNode.NextUUID
	}
	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	//var guardian Guardian
	//
	////get file UUID and keys
	//fileUUID :=
	////check keystore to see if recipient is valid
	//recipient, ok := userlib.KeystoreGet(recipient)
	//if !ok {
	//	return "", errors.New("Recipient is invalid")
	//}
	////checks if user has access to the file
	//fileHeader, err := userdata.checkAccessibility(filename)
	//if err {
	//	return "", errors.New("User doesn't have access to this file")
	//}
	//
	////initialize guardian object
	//newUUID = New()
	//guardian.GuardianUUID = newUUID
	//guardianSymKey := userlib.RandomBytes(userlib.AESKeySize)
	//guardianIV := userlib.RandomBytes(userlib.AESBlockSize)
	//guardianHMAC := userlib.RandomBytes(userlib.AESKeySize)
	//guardianPair := Pair{guardian.GuardianUUID, guardianSymKey, guardianIV, guardianHMAC}
	//
	////generate access token for recipient, encrypt using PKE
	//
	//recPKEKey, ok := userlib.KeystoreGet(recipient)
	//if !ok {
	//	return "", errors.New("Recipient is missing public encryption key")
	//}
	//
	////add recipient’s name to AllowedUser map
	//guardian.AllowedUser = append(guardian.AllowedUser, recipient)
	//
	////encrypt pair struct with recipient's public PKE key
	//encFileUUID, _ := userlib.pkeEnc(recPKEKey, guardianPair.FileUUID)
	//encFileEncKey, _ := userlib.pkeEnc(recPKEKey, guardianPair.SymKey)
	//encFileIV, _ := userlib.pkeEnc(recPKEKey, guardianPair.IV)
	//encFileHmacKey, _ := userlib.pkeEnc(recPKEKey, guardianPair.HMAC)
	//
	////token generation
	//accessToken := Pair{encFileUUID, encFileEncKey, encFileIV, encFileHmacKey}
	//encMsgBytes, _ := json.Marshal(accessToken)
	//sig, _ := userlib.dsSign(userdata.PrivateSignKey, encMsgBytes)
	//magicStringBytes, _ := json.Marshal(SharingPair{encMsgBytes})
	//magic_string = string(magicStringBytes)
	////symEnc for files, PKE for access tokens
	//return magic_string, _
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	//// unwrap sharingPair and verify it with sender's public key
	//var sharingPair SharingPair
	//v := json.Unmarshal([]byte(magic_string), &sharingPair)
	//if v != nil {
	//	return errors.New("Json Error")
	//}
	//senderSignKey, ok := userlib.KeystoreGet(sender + "vfy")
	//if !ok {
	//	return errors.New("Invalid sender")
	//}
	//vfy := userlib.dsVerify(senderSignKey, sharingPair.EncMsg, sharingPair.Signature)
	//if vfy != nil {
	//	return errors.New("Invalid verification")
	//}
	////decrypt message with recipient's private key
	//var pair Pair
	//error := json.Unmarshal(sharingPair.EncMsg, &pair)
	//if error != nil {
	//	return error
	//}
	//fileUUID, error := userlib.pkeDec(userdata.PrivateDecKey, pair.FileUUID)
	//if error != nil {
	//	return error
	//}
	//fileEncKey, error := userlib.pkeDec(userdata.PrivateDecKey, pair.SymKey)
	//if error != nil {
	//	return error
	//}
	//fileIV, error := userlib.pkeDec(userdata.PrivateDecKey, pair.IV)
	//if error != nil {
	//	return error
	//}
	//fileHMAC, error := userlib.pkeDec(userdata.PrivateDecKey, pair.HMAC)
	//if error != nil {
	//	return error
	//}
	//newPair := Pair{fileUUID, fileEncKey, fileIV, fileHMAC}
	//accessible, accesserr := userdata.getAccessibleList()
	//if accesserr != nil {
	//	return
	//}
	//accessible.Shared[filename] = newPair

	//encryptAndStore(guardian, guardianIV, guardianSymKey, guardianHMAC, guardian.GuardianUUID)

	//add pair to recipient's accessible.shared
	//recipient encrypt file with own keys and store on Datastore as well
	//check if file with same name already exists for recipient

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
