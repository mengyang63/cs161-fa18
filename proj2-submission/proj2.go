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
	userlib.DebugMsg("Unmashaled data %v", g.String())

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
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)

	// Contains the HMAC of the username with the password as the key
	Username []byte
	// Argon2Key of password with salt of username to prevent dictionary attacks.
	Password []byte
	// Password salt
	Salt []byte
	// RSA Private Key
	PrivKey userlib.PrivateKey
	// Files shared with user
	Shared map[string]File
	// Files created by user
	Created map[string]File
}

/***************************************************************
                	BEGIN HELPER STRUCTURES
***************************************************************/

// The structure definition for a file record
type File struct {
	// File ID/Unique Identifier
	ID uuid.UUID
	// File Encrypted Key
	Key []byte
	// File MAC key
	MAC []byte
	// File Creator
	Creator []byte
	// // Pointer used for appending to file
	// Next []byte
}

// The structure definition for a pair (defined below)
// Holds (encrypted) data and the corresponding mac of that (encrypted) data
type Pair struct {
	Data []byte
	MAC  []byte
}

// Holds edata and nonce. For use with encrypt2/decrypt2 functions.
type Cipher struct {
	edata []byte
	nonce []byte
}

/***************************************************************
                	END HELPER STRUCTURES
***************************************************************/

/***************************************************************
                	BEGIN HELPER FUNCTIONS
***************************************************************/

// Computes SHA256 hash of data. Uses helpers from userlib
func hash_sha256(data []byte) []byte {
	sha := userlib.NewSHA256()
	sha.Write(data)
	hash := sha.Sum([]byte(""))
	return hash
}

// Computers HMAC for key, data. Uses helpers from userlib
func hmac(key []byte, data []byte) []byte {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	return mac.Sum(nil)
}

// Checks validity of HMAC. Uses helpers from userlib
func hmac_auth(key []byte, data []byte, MAC []byte) bool {
	return userlib.Equal(MAC, hmac(key, data))
}

// Nonce need not be secret
// Given ekey, data: encrypts msg using CFBEncrypter helper function from userlib
func encrypt(ekey []byte, data []byte) []byte {
	edata := make([]byte, userlib.BlockSize+len(data))
	iv := edata[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	encryptor := userlib.CFBEncrypter(ekey, iv)
	encryptor.XORKeyStream(edata[userlib.BlockSize:], data)
	return edata
}

// Given ekey, edata: decrypts edata using CFBDecrypter helper function from userlib
func decrypt(ekey []byte, edata []byte) []byte {
	data := make([]byte, len(edata[userlib.BlockSize:]))
	iv := edata[:userlib.BlockSize]
	decryptor := userlib.CFBDecrypter(ekey, iv)
	decryptor.XORKeyStream(data, edata[userlib.BlockSize:])
	return data
}

// // Given ekey, data: encrypts msg using CFBEncrypter helper function from userlib
// func encrypt_nonce(ekey []byte, data []byte) ([]byte, []byte) {
// 	edata := make([]byte, userlib.BlockSize+len(data))
// 	nonce := edata[:userlib.BlockSize]
// 	copy(nonce, userlib.RandomBytes(userlib.BlockSize))
// 	encryptor := userlib.CFBEncrypter(ekey, nonce)
// 	encryptor.XORKeyStream(edata[userlib.BlockSize:], data)
// 	return edata, nonce
// }

// // Given ekey, edata, nonce: decrypts edata using CFBDecrypter helper function from userlib
// func decrypt_nonce(ekey []byte, edata []byte, nonce []byte) []byte {
// 	data := make([]byte, len(edata[userlib.BlockSize:]))
// 	decryptor := userlib.CFBDecrypter(ekey, nonce)
// 	decryptor.XORKeyStream(data, edata[userlib.BlockSize:])
// 	return data
// }

// https://stackoverflow.com/questions/37884361/concat-multiple-slices-in-golang
func link(src []byte, data []byte, len uint) []byte {
	ret := make([]byte, len)
	copy(ret, src)
	return concat(ret, data)
}

// https://stackoverflow.com/questions/37884361/concat-multiple-slices-in-golang
func concat(head []byte, foot []byte) []byte {
	for _, data := range foot {
		head = append(head, data)
	}
	return head
}

func check_err(err error) {
	if err != nil {
		panic(err)
	}
}

// Converts user into JSON string and encrypts using password. Stored with HMAC.
func SendToDatastore(userdata User) (err error) {
	// Set key as user's password
	// Password is Argon2Key of password with salt to prevent dict attacks.
	key := userdata.Password
	// Marshal userdata
	// https://piazza.com/class/jkmpu2ox8ef6ac?cid=496
	marshaluser, err := json.Marshal(&userdata)
	check_err(err)

	// Uses key to also function as encrypt key and mac for user. Stored in pair.
	// Ke
	key_encrypt := key[userlib.AESKeySize:]
	// Km
	key_mac := key[:userlib.AESKeySize]
	pair_data := encrypt(key_encrypt, marshaluser)
	pair := Pair{pair_data, hmac(key_mac, pair_data)}

	// Add user to users with ID set to UUID(HMAC(Ka, username)) for uniqueness
	path := "users/" + bytesToUUID(hmac(key_mac, []byte(userdata.Username))).String()

	// Marshal encryption key and hmac pair for user
	// https://piazza.com/class/jkmpu2ox8ef6ac?cid=496
	marshalpair, err := json.Marshal(pair)
	check_err(err)

	// Set user in datastore at correct path for retrieval
	userlib.DatastoreSet(path, marshalpair)
	return err
}

/***************************************************************
                	END HELPER FUNCTIONS
***************************************************************/

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
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// Check to see if user already exists
	// _, user_exist := userlib.KeystoreGet(username)
	// if user_exist {
	// 	return nil, errors.New(strings.ToTitle("Entry already exists for user '" + username + "'."))
	// }

	// hmac username w/ password as key
	name := hmac([]byte(password), []byte(username))
	// Use Argon2 to generate pw
	// Set password as Argon2Key of password with salt to prevent dict attacks.
	salt := []byte(username)
	pw := userlib.Argon2Key([]byte(password), salt, uint32(2*userlib.AESKeySize))
	// Generate RSA keys
	rsaPriv, err := userlib.GenerateRSAKey()
	check_err(err)

	// Create File maps
	shared := make(map[string]File)
	owned := make(map[string]File)

	// Populate userdata
	userdata = User{name, pw, salt, *rsaPriv, shared, owned}

	// Set RSA keys for user
	userlib.KeystoreSet(username, userdata.PrivKey.PublicKey)
	// Call helpers function to store user data
	err = SendToDatastore(userdata)
	check_err(err)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Calculate the key that would correspond to the user data entered
	salt := []byte(username)
	usr_key := userlib.Argon2Key([]byte(password), salt, uint32(2*userlib.AESKeySize))

	// Find encrypt and mac keys for pair authentication/anti-tampering checks
	// Ke
	key_encrypt := usr_key[userlib.AESKeySize:]
	// Km
	key_mac := usr_key[:userlib.AESKeySize]

	// Path for provided user using mac key
	name := hmac([]byte(password), []byte(username))
	path := "users/" + bytesToUUID(hmac(key_mac, []byte(name))).String()
	// Fetch user from datastore at provided path
	fetch, ok := userlib.DatastoreGet(path)
	// Check validity
	if !ok {
		return nil, errors.New("User '" + username + "' not found or does not exist.")
	}

	// Unmarshal data for tampering check
	// https://piazza.com/class/jkmpu2ox8ef6ac?cid=496
	var pair Pair
	err = json.Unmarshal(fetch, &pair)
	if err != nil {
		return nil, errors.New("Failed to unmarshal data fetch.")
	}

	// Another anti-tampering measure
	// Ensure hmac of fetch matches
	if !hmac_auth(key_mac, pair.Data, pair.MAC) {
		return nil, errors.New("Tampering detected. File has been corrupted. HMAC verification on user datastore fetch invalid.")
	}

	// Validity of user confirmed. Unmarshal data for return statement!
	var userdata User
	data := decrypt(key_encrypt, pair.Data)
	err = json.Unmarshal(data, &userdata)
	check_err(err)

	return &userdata, err
}

/***************************************************************
                	BEGIN HELPER STRUCTURES
***************************************************************/

/*
File Struct (for reference)
type File struct {
	ID uuid.UUID - File Unique Identifier
	Key []byte - File Encrypted Key
	MAC []byte - File MAC Key
	Creator []byte - File Creator
	Next []byte - Pointer used for appending to file
}
*/

// Note to self: Make sure to update and test all file storing/loading functions
// to make sure that they reflect changes to file structure and don't use the less secure
// User struct maps.
// Contains information about original file
type FileNode struct {
	// Length of file in bytes
	Size uint
	// Tracks total number of edits performed on the file so far
	// Allows us to determine how much space is needed to store file
	// Allows us to properly concat appended edits to original file when loading
	EditCount uint
	// Tracks individual sizes for each FileNode that corresponds to a given file
	// Allows us to determine how much space is needed to store file
	// Allows us to properly concat appended edits to original file when loading
	EditSizeArray []uint
}

// Used similarly to Pair struct
type FilePair struct {
	Data []byte
	MAC  []byte
}

/***************************************************************
                	END HELPER STRUCTURES
***************************************************************/

/***************************************************************
                	BEGIN HELPER FUNCTIONS
***************************************************************/

// Uses file information from FileNode struct to initialize FilePair
// Sets path for file information and stores in Datastore securely
func (userdata *User) StoreFileNodeInfo(filename string, node *FileNode) {
	// Initialize variables for initial permission/validity checks
	var isOwner, isContributor bool
	var file File

	// check to see if user is owner or contributor
	file, isOwner = userdata.Created[filename]
	if !isOwner {
		file, isContributor = userdata.Shared[filename]
		if !isContributor {
			panic(errors.New("Filename invalid or access not permitted."))
		}
	}

	// Marshal (convert to byte array) FileNode struct
	// Will be stored as/used as field in filepair thing I added
	nodemarshal, err := json.Marshal(node)
	check_err(err)

	// Initialize filepair
	// Sets Data/ekey field to marshaled node struct
	// Sets MAC field to HMAC of file's stored MAC field and marshaled node struct
	filepair := FilePair{nodemarshal, hmac(file.MAC, nodemarshal)}

	// Marshal FilePair for proper data storage as byte array
	filepairmarshal, err := json.Marshal(filepair)
	check_err(err)

	// Set path for file info and store in Datastore
	path := "files/info/" + file.ID.String()
	userlib.DatastoreSet(path, filepairmarshal)
}

// Uses filename to verify permissions, load requested file
// Note to self: check permissions, then look at previous function and work backwards
func (userdata *User) GetFileNode(filename string) (filenode *FileNode, err error) {
	// Initialize variables for initial permission/validity checks
	var isOwner, isContributor bool
	var file File

	// check to see if user is owner or contributor
	file, isOwner = userdata.Created[filename]
	if !isOwner {
		file, isContributor = userdata.Shared[filename]
		if !isContributor {
			return nil, errors.New("Filename invalid or access not permitted.")
		}
	}

	// Pointer to path of filenode in Datastore
	path := "files/info/" + file.ID.String()
	// Get filenode data from Datastore
	filepairmarshal, ok := userlib.DatastoreGet(path)
	if !ok {
		return nil, errors.New("File information not found.")
	}

	// Need to unmarshal fetch here
	// Init FilePair and unmarshal fetched data
	var filepair FilePair
	err = json.Unmarshal(filepairmarshal, &filepair)
	if err != nil {
		return nil, errors.New("Failed to unmarshal file pair struct.")
	}

	// Check to see if file has been tampered with by verifying hmac
	tamper := hmac_auth(file.MAC, filepair.Data, filepair.MAC)
	if !tamper {
		return nil, errors.New("Tampering detected. File has been corrupted. HMAC authentication on fetched file information in GetFileNode is invalid.")
	}

	// Permissions verified and filepair validity confirmed.
	// Proceed to unmarshal and return filenode!
	var node FileNode
	err = json.Unmarshal(filepair.Data, &node)
	if err != nil {
		return nil, errors.New("Failed to unmarshal file info struct.")

	}
	return &node, err
}

// Helper function for LoadFile
//
// Loops through all revision and file data for a File file that corresponds to the filename.
// Also requires passing in the associated FileNode node and the relevant datastore fetch.
// Uses these values to assemble complete file data for return
func (userdata *User) LoadFileHelper(filename string, file File, node *FileNode, fetch []byte) (data []byte, err error) {
	var ret []byte
	index := 0
	for i := 0; i < int(node.EditCount); i++ {
		// Calculate efile and filemac from fetched filedata since we stored it smartly!
		// For each loop, we can verify integrity by indexing correctly
		// And retreiving the proper efile and filemac for hmac_auth
		// Note to self: fetch = concat(concat(filedata, filemac), efile)
		// Note to self: EditSizeArray position corresponds to i value in loop
		pos := int(node.EditSizeArray[i])
		step := index + userlib.HashSize
		efile := fetch[step:(step + pos)]
		filemac := fetch[index:step]

		// Calculate filenum marshal for hmac (corresponds to i again!!)
		filenum, err := json.Marshal(i)
		check_err(err)

		// Check to see if file has been tampered with by verifying hmac
		hmac_data := link(efile, filenum, node.EditSizeArray[i])
		tamper := hmac_auth(file.MAC, hmac_data, filemac)
		if !tamper {
			return nil, errors.New("Tampering detected. File has been corrupted. HMAC authentication on fetched file information in LoadFile is invalid.")
		}

		// Proceed to decrypt original message
		msg := decrypt(file.Key, efile)
		ret = concat(ret, msg)

		// Update count for next loop
		index += userlib.HashSize + pos
	}
	return ret, err
}

/***************************************************************
                	END HELPER FUNCTIONS
***************************************************************/

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Populate File struct
	fileUUID := uuid.New()
	file_ekey := userlib.RandomBytes(16)
	file_mkey := userlib.RandomBytes(16)
	// file := File{fileUUID, file_ekey, file_mkey, userdata.Username, userlib.RandomBytes(16)}
	file := File{fileUUID, file_ekey, file_mkey, userdata.Username}

	userdata.Created[filename] = file

	// Encrypt file data for FileNode storage
	efile := encrypt(file_ekey, data)
	file_length := uint(len(efile))

	// Init EditSizeArray
	editsizearray := []uint{file_length}

	// Store data in FileNode
	node := FileNode{file_length, 1, editsizearray}
	userdata.StoreFileNodeInfo(filename, &node)

	// Update here for new structures needed for secure sharing.
	// Need to marshal with EditCount thingy and also
	// Should concatenate together mac and efile to reflect changes
	// For more secure load/store functionality

	// HMAC efile with number of edits to prevent permutation attacks
	// So that we can store file properly/safely
	// Note: changed from marshaling w/ size because attacker might be able to get that info
	filenum, err := json.Marshal(0)
	check_err(err)
	filemac := hmac(file_mkey, link(efile, filenum, file_length))

	// Now that HMAC computed, we can proceed in storing the file in our datastore
	// Create file by storing encrypted file and mac in datastore
	// Concat filedata with filemac, efile and store in Datastore
	// var slice []byte
	// filedata := concat(concat(slice, filemac), efile)
	filedata := concat(filemac, efile)
	path := "files/" + fileUUID.String()
	userlib.DatastoreSet(path, filedata)

	// Update entry for user to reflect changes
	err = SendToDatastore(*userdata)
	check_err(err)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Initialize variables for initial permission/validity checks
	var isOwner, isContributor bool
	var file File

	// check to see if user is owner or contributor
	file, isOwner = userdata.Created[filename]
	if !isOwner {
		file, isContributor = userdata.Shared[filename]
		if !isContributor {
			return errors.New("Filename invalid or access not permitted.")
		}
	}

	// Note to self: look at StoreFile for help
	// Calculate values for file reference
	efile := encrypt(file.Key, data)
	file_length := uint(len(efile))

	// Load filenode
	node, err := userdata.GetFileNode(filename)
	if err != nil {
		return err
	}

	// Get filenum for HMAC from filenode
	filenum, err := json.Marshal(node.EditCount)
	check_err(err)
	// HMAC efile with number of edits to prevent permutation attacks
	// So that we can store file properly/safely
	filemac := hmac(file.MAC, link(efile, filenum, file_length))

	// Update FileNode fields
	node.Size += file_length
	node.EditCount++
	node.EditSizeArray = append(node.EditSizeArray, file_length)
	// Store changes in Datastore, update FilePair, and populate files/info
	userdata.StoreFileNodeInfo(filename, node)

	// Pointer to file path in Datastore
	path := "files/" + file.ID.String()
	fetch, ok := userlib.DatastoreGet(path)
	if !ok {
		return errors.New("File not found.")
	}
	// Concat filemac and efile for secure file storage in Datastore
	fetch = concat(concat(fetch, filemac), efile)
	userlib.DatastoreSet(path, fetch)
	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// Update userdata pointer
	// Added this because otherwise the TestInit one/two thing will fail
	userdata, err = userdata.UpdateUserPointer()
	// Initialize variables for initial permission/validity checks
	var isOwner, isContributor bool
	var file File

	// check to see if user is owner or contributor
	file, isOwner = userdata.Created[filename]
	if !isOwner {
		file, isContributor = userdata.Shared[filename]
		if !isContributor {
			return nil, errors.New("Filename invalid or access not permitted.")
		}
	}

	// Fetch file data from Datastore
	path := "files/" + file.ID.String()
	fetch, ok := userlib.DatastoreGet(path)
	if !ok {
		return nil, errors.New("File not found.")
	}

	// Get filenode to return proper data for user request
	node, err := userdata.GetFileNode(filename)
	if err != nil {
		return nil, err
	}

	// Send relevant data to helper function
	// Loops through all revision and file data to assemble complete file data for return
	var ret []byte
	ret, err = userdata.LoadFileHelper(filename, file, node, fetch)
	return ret, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	// Stores complete FileNode data conveniently
	// Note: needs to be converted to byte array first via marshal call
	Data []byte
	// No longer need this
	// // File location in datastore for quick reference
	// Loc []byte
}

/***************************************************************
                	END HELPER STRUCTURES
***************************************************************/

// Package together only the data relevant for sharing for secure sending
// User requires a sharingRecord (key pointing to something
// in the datastore to share with the recipient.) This enables the recipient
// to access the encrypted file as well for reading/appending.
// Also should use RSA encryption for confidentiality/integrity of file
type Packet struct {
	// Pointer to sharingRecord
	Record sharingRecord
	// RSA Signature
	// Necessary for secure encryption of data when sharing with other users
	RSA []byte
}

/***************************************************************
                	END HELPER STRUCTURES
***************************************************************/
/***************************************************************
                	BEGIN HELPER FUNCTIONS
***************************************************************/

// Make sure pointer for userdata is up to date. Basically a copy-paste of GetUser.
func UpdateUserdata(name []byte, usr_key []byte) (userdataptr *User, err error) {
	// Find encrypt and mac keys for pair authentication/anti-tampering checks
	// Ke
	key_encrypt := usr_key[userlib.AESKeySize:]
	// Km
	key_mac := usr_key[:userlib.AESKeySize]

	// Path for provided user using mac key
	path := "users/" + bytesToUUID(hmac(key_mac, []byte(name))).String()
	// Fetch user from datastore at provided path
	fetch, ok := userlib.DatastoreGet(path)
	// Check validity
	if !ok {
		return nil, errors.New("User not found or does not exist.")
	}

	// Unmarshal data for tampering check
	// https://piazza.com/class/jkmpu2ox8ef6ac?cid=496
	var pair Pair
	err = json.Unmarshal(fetch, &pair)
	if err != nil {
		return nil, errors.New("Failed to unmarshal data fetch.")
	}

	// Another anti-tampering measure
	// Ensure hmac of fetch matches
	if !hmac_auth(key_mac, pair.Data, pair.MAC) {
		return nil, errors.New("Tampering detected. File has been corrupted. HMAC verification on user datastore fetch invalid.")
	}

	// Validity of user confirmed. Unmarshal data for return statement!
	var userdata User
	data := decrypt(key_encrypt, pair.Data)
	err = json.Unmarshal(data, &userdata)
	check_err(err)

	return &userdata, err
}

// Update pointer to userdata
func (userdata *User) UpdateUserPointer() (usr *User, err error) {
	// update pointer to ensure no tampering
	update, err := UpdateUserdata(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}
	return update, err
}

// Check file permissions
func (userdata *User) CheckPermissions(filename string) (file *File, err error) {
	// update pointer to ensure no tampering
	userdata, err = userdata.UpdateUserPointer()

	// check to see if user is owner or contributor
	fetch, ok := userdata.Created[filename]
	if !ok {
		fetch, ok = userdata.Shared[filename]
		if !ok {
			return nil, errors.New("Filename invalid or access not permitted.")
		}
	}
	return &fetch, err
}

/***************************************************************
                	BEGIN HELPER FUNCTIONS
***************************************************************/

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	// UPDATE SHAREFILE TO REFLECT MORE SECURE/MEW USER AND FILE STRUCTURE
	// loc := userdata.Files[filename]
	// fkey := userdata.Keys[filename]
	// rsakey, err1 := userlib.KeystoreGet(recipient)
	// file, err2 := userlib.DatastoreGet(loc)

	// Deleted (most of) old stuff. Kept a bit in comment for help with writing the code below.
	// NEW STUFF:

	// Check permissions **Don't actually need since this is performed in updated checkpermissions
	// var isOwner, isContributor bool
	// var file File

	// // check to see if user is owner or contributor
	// file, isOwner = userdata.Created[filename]
	// if !isOwner {
	// 	file, isContributor = userdata.Shared[filename]
	// 	if !isContributor {
	// 		return nil, errors.New("Filename invalid or access not permitted.")
	// 	}
	// }

	// Get file, check permissions, and check for errors (in case file does not exist, etc.)
	file, err := userdata.CheckPermissions(filename)
	if err != nil {
		return "", err
	}
	// Convert node struct into bytes using marshal
	filemarshal, err := json.Marshal(file)
	check_err(err)

	// Fetch recipient's rsa key from keystore using userlib
	// Note to self: Userlib call returns value rsa.PublicKey, ok bool
	rsakey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("Could not find RSA public key for recipient '" + recipient + "'.")
	}

	// Permissions checked, node and key fetched.
	// Encrypt filenode (marshal first!) as msg using recipient key
	// Userlib call returns []byte, err
	efile, err := userlib.RSAEncrypt(&rsakey, filemarshal, []byte(""))
	// FIXED RSA ENCRYPTION BUG BY REMOVING CREATOR AND NEXT POINTERS IN FILE
	// This reduced the size and allowed it to be encrypted, so not getting the
	// "Message too long" error anymore. Also had to rework a bunch of other file
	// functions and ideas to accommodate this...
	// userlib.DebugMsg("Reached RSA Encrypt.")
	check_err(err)

	// Sign with user's private key for confidentiality/integrity
	sig, err := userlib.RSASign(&userdata.PrivKey, efile)
	// userlib.DebugMsg("Reached RSA Sign.")
	check_err(err)

	// Not storing location in User struct anymore
	// rec := sharingRecord{efile, location}

	// Assemble sharingRecord
	rec := sharingRecord{efile}

	// Assemble packet
	packet := Packet{rec, sig}

	// Assemble packet into message by marshaling it and convert to string for ret
	packetmashal, err := json.Marshal(packet)
	msgid = string(packetmashal)

	return msgid, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	// Convert back to byte from string (see end of StoreFile)
	packetmarshal := []byte(msgid)

	// Unmarshal packet
	// https://piazza.com/class/jkmpu2ox8ef6ac?cid=496
	var packet Packet
	err := json.Unmarshal(packetmarshal, &packet)
	if err != nil {
		return errors.New("Failed to unmarshal packet in call to ReceiveFile.")
	}

	// Once packet is unmarshaled, check integrity using RSA
	// Get sender key
	rsakey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("Public key not found for sender '" + sender + "'.")
	}

	// Verify message using sender key by checking verified (should be nil if no errors encountered)
	verified := userlib.RSAVerify(&rsakey, packet.Record.Data, packet.RSA)
	if verified != nil {
		return errors.New("Encountered error when verifying packet using RSA. Tampering detected.")
	}

	// If verification succeeds, go ahead and decrypt message!
	filemarshal, err := userlib.RSADecrypt(&userdata.PrivKey, packet.Record.Data, []byte(""))

	// Unmarshal filenode that has been shared
	// https://piazza.com/class/jkmpu2ox8ef6ac?cid=496
	var file File
	err = json.Unmarshal(filemarshal, &file)
	if err != nil {
		return errors.New("Failed to unmarshal file in call to ReceiveFile.")
	}

	userdata.Shared[filename] = file
	err = SendToDatastore(*userdata)
	check_err(err)

	return err
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// Update user pointer and check if file created by user
	userdata, err = userdata.UpdateUserPointer()
	file, ok := userdata.Created[filename]
	if !ok {
		return errors.New("File not created by user.")
	}

	// If permissions confirmed, proceed to load file's byte data
	data, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	// All necessary parameters attained. Revoke all the things!
	// Stomp all over the file's associated data to make it entirely useless.

	// Change FileNode data and path
	// Get original ID but change ekey, mkey to new, random values
	// So basically, create a bunch 'o junk.
	id := file.ID.String()
	file_ekey := userlib.RandomBytes(16)
	file_mkey := userlib.RandomBytes(16)

	// Note to self: look at StoreFile and its helpers for implementation

	// Encrypt file data with new keys
	efile := encrypt(file_ekey, data)
	file_length := uint(len(efile))

	// Init EditSizeArray
	editsizearray := []uint{file_length}

	// Create NEW FileNode and store data in it
	node := FileNode{file_length, 1, editsizearray}
	// Call StoreFileNodeInfo to store junk
	// This will also fill the FilePair with some garbage and trash the Datastore!
	// Need to store mkey before this call. Data is sufficiently mush if we just don't store ekey.
	file.MAC = file_mkey
	userdata.StoreFileNodeInfo(filename, &node)

	// Delete data that was muddied in previous call.
	nodepath := "files/info/" + id
	userlib.DatastoreDelete(nodepath)

	// Override old values with junk and delete.
	path := "files/" + id
	userlib.DatastoreSet(path, efile)
	userlib.DatastoreDelete(path)

	// Call StoreFile to essentially move file to new location (as if it were brand new).
	userdata.StoreFile(filename, data)

	return err
}
