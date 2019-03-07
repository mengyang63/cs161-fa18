package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
	)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
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
	userlib.DebugMsg("Unmarshaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username []byte
	PrivateKey *userlib.PrivateKey

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type EncryptedUser struct {
	// Encrypted data
	EncryptedData []byte
	// HMAC Tag
	HMACTag []byte
}

type Metadata struct {
	// Deterministic Key
	EncryptionKey []byte
	// HMAC Key
	HMACKey []byte
	// Nonce
	Nonce []byte
	// File pointer
	FilePointer []byte
}

type File struct {
	// File data
	FileData []byte
	// HMAC Tag
	HMACTag []byte
	// pointer to appended file
	AppendedFile []byte
}

type Share struct {
	// Metadata to share
	ToShare []byte
	// RSA Signature
	RSASignature []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
/**
InitUser(username string, password string) MUST take the
user’s password, which is assumed to have good entropy, and use this to help populate
the User data structure (including generating at least one random RSA key),
securely store a copy of the data structure in the data store, register a public key in
the keystore, and return the newly populated user data structure. The user’s name
MUST be confidential to the data store.
**/
func InitUser(username string, password string) (userdataptr *User, err error) {
	// make user
	var userdata User
	userdata.Username = []byte(username)
	
	// argon2 gen
	var argon []byte 
	argon = userlib.Argon2Key([]byte(password), []byte(username), 64)

	// keygen
	namevalue := argon[0:16]
	ekey := argon[16:32]
	nonce := argon[32:48]
	hmkey := argon[48:64]

	// keystore set
	var key *userlib.PrivateKey
	key, err = userlib.GenerateRSAKey()
	userlib.KeystoreSet(username, key.PublicKey)
	userdata.PrivateKey = key
	
	// marshalling data
	rawdata, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	// encrypting data
	var edata = make([]byte, len(rawdata))
	encryptor := userlib.CFBEncrypter(ekey, nonce)
	encryptor.XORKeyStream(edata, rawdata)

	// hmac
	hmac := userlib.NewHMAC(hmkey)
	hmac.Write(edata)
	tag := hmac.Sum([]byte(""))

	// filling EncryptedUser
	var encrypted EncryptedUser
	encrypted.EncryptedData = edata
	encrypted.HMACTag = tag

	// marshalling EncryptedUser
	encdata, err := json.Marshal(encrypted)
	if err != nil {
		return nil, err
	}

	// datastore set
	userlib.DatastoreSet(string(namevalue), encdata)

	// return
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	// argon2 gen
	var argon []byte 
	argon = userlib.Argon2Key([]byte(password), []byte(username), 64)

	// keygen
	namevalue := argon[0:16]
	ekey := argon[16:32]
	nonce := argon[32:48]
	hmkey := argon[48:64]

	// datastore get
	encUserdata, ok := userlib.DatastoreGet(string(namevalue))
	if !ok {
		return nil, err
	}

	// unmarshaling encrypted user
	var encryptedUserdata EncryptedUser
	err = json.Unmarshal(encUserdata, &encryptedUserdata)
	if err != nil {
		return nil, err
	}
	
	// pulling info from encrypted user
	edata := encryptedUserdata.EncryptedData
	encUsertag := encryptedUserdata.HMACTag

	// hmac
	hmac := userlib.NewHMAC(hmkey)
	hmac.Write(edata)
	tag := hmac.Sum([]byte(""))

	// hmac compare
	if !userlib.Equal(encUsertag, tag) {
		return nil, err
	}
	
	// decrypt userdata
	var decdata = make([]byte, len(edata))
	decryptor := userlib.CFBDecrypter(ekey, nonce)
	decryptor.XORKeyStream(decdata, edata)

	// unmarshal userdata to return
	var userdata *User
	err = json.Unmarshal(decdata, &userdata)
	if err != nil {
		return nil, err
	}

	// return
	return userdata, err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// argon2 gen
	var argon []byte
	argon = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 64)

	// keygen
	namevalue := string(argon[0:16])
	ekey := argon[16:32]
	nonce := argon[32:48]
	hmkey := argon[48:64]

	// make file object
	var file File

	// encrypting file data
	var edata = make([]byte, len(data))
	encryptor := userlib.CFBEncrypter(ekey, nonce)
	encryptor.XORKeyStream(edata, data)

	// hmac
	hmac := userlib.NewHMAC(hmkey)
	hmac.Write(edata)
	tag := hmac.Sum([]byte(""))

	// fill into file
	file.FileData = edata
	file.HMACTag = tag

	// check to make sure we overwrite file if it already exists
	existingEncMarshalMetadata, ok := userlib.DatastoreGet(namevalue)
	var fileLoc []byte
	if ok {
		// decrypt RSA metadata
		privKey := userdata.PrivateKey
		rtag := []byte(userdata.Username)
		marshalMetadata, _ := userlib.RSADecrypt(privKey, existingEncMarshalMetadata, rtag)

		// unmarshal metadata
		var existingMetadata Metadata
		_ = json.Unmarshal(marshalMetadata, &existingMetadata)

		// point to old file location for overwrite
		fileLoc = existingMetadata.FilePointer
	} else {
		// store file into datastore with random location
		fileLoc = userlib.RandomBytes(16)
	}

	// marshal file for storing
	filedata, _ := json.Marshal(file)

	// store file
	userlib.DatastoreSet(string(fileLoc), filedata)

	// make metadata object
	var metadata Metadata
	metadata.EncryptionKey = ekey
	metadata.HMACKey = hmkey
	metadata.Nonce = nonce
	metadata.FilePointer = fileLoc

	// marshal metadata for storing
	marshalMetadata, _ := json.Marshal(metadata)

	// encrypt metadata via RSA (not sure if needed yet, perhaps for share)
	pubKey := userdata.PrivateKey.PublicKey
	msg := marshalMetadata
	rtag := []byte(userdata.Username)
	encMarshalMetadata, _ := userlib.RSAEncrypt(&pubKey, msg, rtag)

	// store metadata
	userlib.DatastoreSet(namevalue, encMarshalMetadata)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// argon2 gen
	var argon []byte
	argon = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 64)

	// keygen
	namevalue := string(argon[0:16])
	ekey := argon[16:32]
	nonce := argon[32:48]
	hmkey := argon[48:64]

	// get metadata from datastore
	encMarshalMetadata, ok := userlib.DatastoreGet(namevalue)
	if !ok {
		return err
	}

	// decrypt RSA metadata
	privKey := userdata.PrivateKey
	rtag := []byte(userdata.Username)
	marshalMetadata, err := userlib.RSADecrypt(privKey, encMarshalMetadata, rtag)

	// unmarshal metadata
	var metadata Metadata
	err = json.Unmarshal(marshalMetadata, &metadata)
	if err != nil {
		return err
	}

	// get file from random location in datastore
	marshalFile, ok := userlib.DatastoreGet(string(metadata.FilePointer))
	if !ok {
		return err
	}

	// unmarshal file
	var file File
	err = json.Unmarshal(marshalFile, &file)
	if err != nil {
		return err
	}

	// pulling appended file info from file
	nextFile := file.AppendedFile

	// saving initial file location
	curFileLoc := metadata.FilePointer

	for nextFile != nil {
		// get file from random location in datastore
		nextMarshalFile, ok := userlib.DatastoreGet(string(nextFile))
		if !ok {
			return err
		}

		// unmarshal file
		var appended File
		err = json.Unmarshal(nextMarshalFile, &appended)
		if err != nil {
			return err
		}

		// saving current file location for further reference
		curFileLoc = nextFile

		// pulling next appended file info from file
		nextFile = appended.AppendedFile
	}

	// make file object
	var toAppend File

	// encrypting to be appended file data
	var edata = make([]byte, len(data))
	encryptor := userlib.CFBEncrypter(ekey, nonce)
	encryptor.XORKeyStream(edata, data)

	// hmac
	hmac := userlib.NewHMAC(hmkey)
	hmac.Write(edata)
	tag := hmac.Sum([]byte(""))

	// fill into file
	toAppend.FileData = edata
	toAppend.HMACTag = tag

	// store file into datastore with random location
	var fileLoc = userlib.RandomBytes(16)

	// marshal file for storing
	toAppendMarshal, _ := json.Marshal(toAppend)

	// store file
	userlib.DatastoreSet(string(fileLoc), toAppendMarshal)


	// get file from random location in datastore
	curMarshalFile, ok := userlib.DatastoreGet(string(curFileLoc))
	if !ok {
		return err
	}

	// unmarshal file
	var cur File
	err = json.Unmarshal(curMarshalFile, &cur)
	if err != nil {
		return err
	}

	// attach appended file
	cur.AppendedFile = fileLoc


	// remarshal file
	curRemarshalFile, err := json.Marshal(cur)

	// storing current file back in datastore
	userlib.DatastoreSet(string(curFileLoc), curRemarshalFile)

	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// argon2 gen
	var argon []byte
	argon = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 64)

	// keygen
	namevalue := string(argon[0:16])

	// get metadata from datastore
	encMarshalMetadata, ok := userlib.DatastoreGet(namevalue)
	if !ok {
		return nil, err
	}

	// decrypt RSA metadata
	privKey := userdata.PrivateKey
	rtag := []byte(userdata.Username)
	marshalMetadata, err := userlib.RSADecrypt(privKey, encMarshalMetadata, rtag)

	// unmarshal metadata
	var metadata Metadata
	err = json.Unmarshal(marshalMetadata, &metadata)
	if err != nil {
		return nil, err
	}

	// get file from random location in datastore
	marshalFile, ok := userlib.DatastoreGet(string(metadata.FilePointer))
	if !ok {
		return nil, err
	}

	// unmarshal file
	var file File
	err = json.Unmarshal(marshalFile, &file)
	if err != nil {
		return nil, err
	}

	// pulling info from file
	eFile := file.FileData
	encFiletag := file.HMACTag
	nextFile := file.AppendedFile

	// hmac
	hmac := userlib.NewHMAC(metadata.HMACKey)
	hmac.Write(eFile)
	tag := hmac.Sum([]byte(""))

	// hmac compare
	if !userlib.Equal(encFiletag, tag) {
		return nil, err
	}

	// decrypt filedata
	var decFile = make([]byte, len(eFile))
	decryptor := userlib.CFBDecrypter(metadata.EncryptionKey, metadata.Nonce)
	decryptor.XORKeyStream(decFile, eFile)


	// de appender clause
	for nextFile != nil {
		// get file from random location in datastore
		nextMarshalFile, ok := userlib.DatastoreGet(string(nextFile))
		if !ok {
			return nil, err
		}

		// unmarshal file
		var appended File
		err = json.Unmarshal(nextMarshalFile, &appended)
		if err != nil {
			return nil, err
		}

		// pulling info from file
		nextEFile := appended.FileData
		nextEncFiletag := appended.HMACTag
		nextFile = appended.AppendedFile

		// hmac
		hmac := userlib.NewHMAC(metadata.HMACKey)
		hmac.Write(nextEFile)
		tag := hmac.Sum([]byte(""))

		// hmac compare
		if !userlib.Equal(nextEncFiletag, tag) {
			return nil, err
		}

		// decrypt filedata
		var nextDecFile = make([]byte, len(nextEFile))
		nextDecryptor := userlib.CFBDecrypter(metadata.EncryptionKey, metadata.Nonce)
		nextDecryptor.XORKeyStream(nextDecFile, nextEFile)

		// add to decFile
		decFile = appendByteArrs(decFile, nextDecFile)
	}

	return decFile, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type SharingRecord struct {

}
// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	// creating sharingRecord
	var share Share

	// argon2 gen
	var argon []byte
	argon = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 64)

	// keygen
	namevalue := string(argon[0:16])

	// get metadata from datastore
	encMarshalMetadata, ok := userlib.DatastoreGet(namevalue)
	if !ok {
		return "" , err
	}

	// decrypt RSA metadata
	privKey := userdata.PrivateKey
	rtag := []byte(userdata.Username)
	marshalMetadata, err := userlib.RSADecrypt(privKey, encMarshalMetadata, rtag)

	// re encrypt RSA metadata for recipient (with their public key)
	pubKey, _ := userlib.KeystoreGet(recipient) // Just an abstract thing saying that pubKey is just a RSA Public Key struct
	msg := marshalMetadata
	tag := []byte(recipient) // You can set the tag to whatever but it MUST be the same for encryption and decryption!
	RSAencryptedMessage, err := userlib.RSAEncrypt(&pubKey, msg, tag) // NOTE that we have to pass in the address of the public key struct since rsa encrypt takes in a pointer and not the object itself.

	// RSA Sign Metadata
	sig, err := userlib.RSASign(privKey, RSAencryptedMessage)
	share.RSASignature = sig
	if err != nil {
		return "", err
	}

	// setting share's metadata
	share.ToShare = RSAencryptedMessage

	// marshal share
	marshalShare, err := json.Marshal(share)
	if err != nil {
		return "", err
	}

	// convert to string to send
	toRecipient := string(marshalShare)

	return toRecipient, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	// argon2 gen
	var argon []byte
	argon = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 64)

	// keygen
	namevalue := string(argon[0:16])

	// unmarshal message
	var share Share
	sharedMsg := []byte(msgid)
	err := json.Unmarshal(sharedMsg, &share)
	if err != nil {
		return err
	}

	// Get data from message
	msgData := share.ToShare
	RSASignature := share.RSASignature

	// get senders public key for verification
	pubKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return err
	}

	// verification here somehow fails, idk why?

	// verify sender via RSASign
	err = userlib.RSAVerify(&pubKey, msgData, RSASignature)
	if err != nil {
		return err
	}

	// store metadata in datastore
	userlib.DatastoreSet(namevalue, msgData)

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// argon2 gen
	var argon []byte
	argon = userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 64)

	// keygen, will use to verify owner status
	namevalue := string(argon[0:16])
	ekey := argon[16:32]
	nonce := argon[32:48]
	hmkey := argon[48:64]

	// get metadata from datastore
	encMarshalMetadata, ok := userlib.DatastoreGet(namevalue)
	if !ok {
		return err
	}

	// decrypt RSA metadata
	privKey := userdata.PrivateKey
	rtag := []byte(userdata.Username)
	marshalMetadata, err := userlib.RSADecrypt(privKey, encMarshalMetadata, rtag)

	// unmarshal metadata
	var metadata Metadata
	err = json.Unmarshal(marshalMetadata, &metadata)
	if err != nil {
		return err
	}

	// revoke access by setting new location for file (doesn't delete old file location)
	if userlib.Equal(ekey, metadata.EncryptionKey) &&
		userlib.Equal(nonce, metadata.Nonce) &&
		userlib.Equal(hmkey, metadata.HMACKey) {
		newFileLoc := userlib.RandomBytes(16)
		for userlib.Equal(newFileLoc, []byte(namevalue)) {
			newFileLoc = userlib.RandomBytes(16)
		}
	}
	return
}

// concatenating signature, edata, and tag (in that order)
func appendByteArrs(byteArr1 []byte, byteArr2 []byte) (concat []byte) {
	return append(byteArr1, byteArr2...)
}