package stellarwallet

import(
	"fmt"
	"errors"
	"strings"
	"bytes"
	"unicode"

	"crypto/sha1"	
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"

	"container/list"

	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"	
	"golang.org/x/crypto/ed25519"

	"github.com/bartekn/go-bip39"
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/exp/crypto/derivation"
	//"github.com/stellar/go/keypair"

	//"encoding/hex"

	"encoding/binary"
)

const walletVersion = 1

const stellarwalletSeed = "sellarwallet seed"

const masterSeedLen = 32
const bip39SeedLen = 64
const accountSeedLen = 32

const AccountTypeUndefined = 0 // Account type undefined
const AccountTypeSEP0005 = 1 // Account is SEP0005 derived from the BIP39 seed
const AccountTypeRandom = 2  // Account is based on a randomly generated key
const AccountTypeWatching = 3 // Account has a public key only 
const AccountTypeAddressBook = 4 // Account is an address book entry (public key only) 

const WalletFlagSignDescription = 1<<0
const WalletFlagSignAccounts = 1<<1
const WalletFlagSignAccountMemo = 1<<2
const WalletFlagSignAssets = 1<<3
const WalletFlagSignTradingPairs = 1<<4
const WalletFlagSignAll = WalletFlagSignDescription|WalletFlagSignAccounts|WalletFlagSignAccountMemo|WalletFlagSignAssets|WalletFlagSignTradingPairs
const WalletFlagAll = WalletFlagSignDescription|WalletFlagSignAccounts|WalletFlagSignAccountMemo|WalletFlagSignAssets|WalletFlagSignTradingPairs



type WalletFlags uint64

// error returned for invalid password
var ErrorInvalidPassword = errors.New("invalid password")

type Account struct {
	wallet *Wallet
	active bool
	desc string
	accountType uint16
	publicKey string
	privateKey []byte
	sep0005DerivationPath string
	memoText string
	memoId uint64
	memoIdSet bool

	signature []byte
}

type Asset struct {
	wallet *Wallet
	active bool
	tradingPairLink *list.List

	desc string
	issuer string
	assetId string

	signature []byte
}	

type TradingPair struct {
	wallet *Wallet
	active bool

	desc string
	asset1 *Asset
	asset2 *Asset

	signature []byte
}

type Wallet struct {
	flags WalletFlags  		// wallet flags
	desc string

	masterSeed []byte    // 256bit entropy
	bip39Seed []byte     // derived from masterSeed and mnemonic password

	sep0005AccountCount uint16

	accounts []*Account
	assets []*Asset
	tradingPairs []*TradingPair

	signature []byte
}

var (
	gSelfTestDone = false
	gSelfTestStatus error

)

// EraseByteBuffer wipes content of given byte buffer.
func EraseByteBuffer(b []byte) {
	if b != nil {
		for i := range b {
			b[i] = 0
		}
	}
}

// EraseString wipes content of given string.
func EraseString(s *string) {
	EraseByteBuffer([]byte(*s))
}

// CheckDescription checks for valid wallet, account or asset description string.
// If given description is not valid returned error contains details about failed check.
func CheckDescription(s string) error {
	if len(s) > 2000 {
		return errors.New("exceeds max length (2000 characters)")
	}

	return nil
}

// CheckMemoText checks for valid transaction memo text. 
// If given memo text is not valid returned error contains details about failed check.
func CheckMemoText(s string) error {
	if len(s) > 28 {
		return errors.New("exceeds max length (28 characters)")
	}

	return nil
}

// CheckPublicKey checks if given string is a valid public account key.
func CheckPublicKey(s string) bool {
	_, err := strkey.Decode(strkey.VersionByteAccountID, s)

	if err != nil {
		return false
	}

	return true
}

// CheckPrivateKey checks if given string is a valid private account key (seed).
func CheckPrivateKey(s *string) bool {
	_, err := strkey.Decode(strkey.VersionByteSeed, *s)

	if err != nil {
		return false
	}

	return true

}

// CheckAssetId checks if given string is a valid asset id. 
// If not valid returned error contains details about failed check.
func CheckAssetId(s string) error {
	l := len(s)

	if l < 1 || l > 12 {
		return errors.New("invalid length")
	}

	for _, c := range s {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c)) {
			return errors.New("invalid character: " + string(c))
		}
	}

	return nil
}

// CheckMnemonicWord checks if given string is a valid mnemonic word.
// Can be used by applications to immediately check validity of entered mnemonic words for wallet recovery.
func CheckMnemonicWord(s string) bool {
	_, found := bip39.ReverseWordMap[s]

	return found
}

func checkWalletFlags(flags WalletFlags) {
	var validFlags WalletFlags

	validFlags = WalletFlagAll

	if (flags & ^validFlags) != 0 {
		panic("Invalid wallet flags")
	}
}

// NewWallet creates a new empty wallet, encrypted with given password.
// Each new wallet has an associated encrypted 256 bit entropy, which is the source for the mnemonic words list,
// i.e. the mnemonic word list is defined when a new wallet is created.
// This method panics if invalid wallet flags are given.
// This method panics if the build-in self test fails (see method SelfTest()).
func NewWallet(flags WalletFlags, password *string) *Wallet {
	if err := SelfTest(); err != nil {
		panic(err.Error())
	}

	checkWalletFlags(flags)

	wallet := new(Wallet)

	wallet.flags = flags

	entropy, err := bip39.NewEntropy(256)
	
	if err != nil {
		panic(err)
	}
	
	key := deriveAesKey(password)

	wallet.encryptMasterSeed(entropy, key)

	sk := wallet.deriveSigningKey(key)
	wallet.sign(sk)
	EraseByteBuffer(sk)

	EraseByteBuffer(entropy)
	EraseByteBuffer(key)
	
	return wallet
}

// NewWalletFromMnemonic creates a new wallet from a given mnemonic word list and mnemonic password and encrypts it with given wallet password.
// This method is used to recover a wallet from a mnemonic word list and password.
// If the mnemonic word list is invalid, nil will be returned.
// An invalid mnemonic password is not detected so that it cannot be reported to the user. If a wrong mnemonic password is provided,
// another set of account seeds will be generated and the user will not see his funds.  
// This method panics if the build-in self test fails (see method SelfTest()).
func NewWalletFromMnemonic(flags WalletFlags, walletPassword *string, mnemonic []string, mnemonicPassword *string) *Wallet {
	if err := SelfTest(); err != nil {
		panic(err.Error())
	}

	checkWalletFlags(flags)

	w := new(Wallet)

	w.flags = flags

	key := deriveAesKey(walletPassword)
	defer EraseByteBuffer(key)

	seed, err := bip39.MnemonicToByteArray(strings.Join(mnemonic, " "))
	if err != nil {
		return nil
	}
	defer EraseByteBuffer(seed)
	
	seed = seed[:masterSeedLen]

	w.encryptMasterSeed(seed, key)

	if !w.generateBip39Seed(key, mnemonic, mnemonicPassword) {
		return nil
	}

	sk := w.deriveSigningKey(key)
	w.sign(sk)
	EraseByteBuffer(sk)

	return w
}


// RecoverAccounts can be used to recover accounts after a wallet was recovered from
// a mnemonic word list. It will generate accounts and check if they are funded
// via provided function fundedCheck(). fundedCheck() must be a functions that
// checks on the Stellar network if the given account is funded and returns true in case.
// maxGap defines the maximum number of unfunded accounts being accepted until the search stops.
func (w *Wallet) RecoverAccounts(walletPassword *string, maxGap uint16, fundedCheck func (adr string) bool) {
	key := w.checkPassword(walletPassword)

	if key == nil {
		return // invalid password
	}

	defer EraseByteBuffer(key)

	sk := w.deriveSigningKey(key)
	defer EraseByteBuffer(sk)

	var lastFound = w.sep0005AccountCount

	for {
		a := w.generateAccount(key, sk)

		if fundedCheck(a.PublicKey()) {
			lastFound = w.sep0005AccountCount
		} else {
			w.DeleteAccount(a)
		}

		if w.sep0005AccountCount - lastFound > maxGap {
			break
		}
	}

	w.sep0005AccountCount = lastFound

	w.sign(sk)
}

// ImportBinary creates a new wallet from an exported binary serialization of the wallet content.
// This method can be used to restore a wallet from a permanent storage location.
// This method panics if the build-in self test fails (see method SelfTest()).
func ImportBinary(buf []byte) (w *Wallet, err error) {
	if err := SelfTest(); err != nil {
		panic(err.Error())
	}

	w = new(Wallet)

	err = w.readFromBufferCompressed(buf)

	if err != nil {
		return nil, err
	}

	return w, nil
}

// ImportBase64 creates a new wallet from an exported ascii (base 64) serialization of the wallet content.
// This method can be used to restore a wallet from a permanent storage location.
// This method panics if the build-in self test fails (see method SelfTest()).
func ImportBase64(data string) (w *Wallet, err error) {
	if err := SelfTest(); err != nil {
		panic(err.Error())
	}

	buf, err := base64.StdEncoding.DecodeString(data)

	if err != nil {
		return nil, errors.New("base64 decoding failed: " + err.Error())
	}

	w = new(Wallet)

	err = w.readFromBufferCompressed(buf)

	if err != nil {
		return nil, err
	}

	return w, nil
}

// ExportBinary creates a binary serialization of the wallet content, e.g. for permanent storage of the wallet on disk.
func (w *Wallet)ExportBinary() []byte {
	return w.writeToBufferCompressed()
}

// ExportBase64 creates an ascii (base 64) serialization of the wallet content, e.g. for permanent storage of the wallet on disk.
func (w *Wallet)ExportBase64() string {
	buf := w.writeToBufferCompressed()

	if buf == nil {
		return ""
	} else {
		return base64.StdEncoding.EncodeToString(buf)
	}
}

// Flags returns the currently set wallet flags.
func (w *Wallet)Flags() WalletFlags {
	return w.flags
}

// SetFlags sets new wallet flags.
// walletPassword is required to re-build the signatures.
// This function panics if invalid wallet flags are given.
// Return false if an invalid wallet password was given.
func (w *Wallet)SetFlags(flags WalletFlags, walletPassword *string) bool {
	checkWalletFlags(flags)

	key := w.checkPassword(walletPassword)
	if key == nil {
		return false
	}
	defer EraseByteBuffer(key)

	sk := w.deriveSigningKey(key)
	defer EraseByteBuffer(sk)
	w.flags = flags

	w.signAll(sk)

	return true
}


// Returns true if specified wallet flag is set.
func (w *Wallet)isFlagSet(flag WalletFlags) bool {
	if (w.flags&flag) != 0 {
		return true
	}
	return false
}

// CheckIntegrity verifies the consistency of the wallet data and ensures that
// the not encrypted data of the wallet has not been modified (e.g. by an attacker).
// Returns true on successful integrity verification, else false.
// If the given walletPassword is invalid, false will be returned as well.
func (w *Wallet)CheckIntegrity(walletPassword *string) bool {

	key := w.checkPassword(walletPassword)
	if key == nil {
		return false
	}
	defer EraseByteBuffer(key)

	if !w.checkConsistency(key) {
		return false
	}

	if !w.checkSignatures(key) {
		return false
	}
	return true
}

func (w *Wallet)checkConsistency(key []byte) bool {
	for _, a := range w.accounts {
		if !a.checkConsistency(key) {
			return false
		}
	}

	for _, a := range w.assets {
		if !a.checkConsistency() {
			return false
		}
	}

	for _, tp := range w.tradingPairs {
		if !tp.checkConsistency() {
			return false
		}
	}

	return true
}

func (w *Wallet)checkSignatures(key []byte) bool {
	sk := w.deriveSigningKey(key)
	if  sk == nil {
		return false
	}
	defer EraseByteBuffer(sk)

	pk := sk.Public().(ed25519.PublicKey)

	if !w.checkSignature(pk) {
		return false
	}

	for _, a := range w.accounts {
		if !a.checkSignature(pk) {
			return false
		}
	}

	for _, a := range w.assets {
		if !a.checkSignature(pk) {
			return false
		}
	}

	for _, tp := range w.tradingPairs {
		if !tp.checkSignature(pk) {
			return false
		}
	}

	return true
}

// Clears all accounts.
func (w *Wallet)clearAccounts() {
	for _, a := range w.accounts {
		a.active = false
		a.privateKey = nil
		a.publicKey = ""
		a.sep0005DerivationPath = ""
	}
}

// Description returns the optional wallet description.
func (w *Wallet)Description() string {
	return w.desc
}

// SetDescription sets wallet description.
// walletPassword is required only if wallet flag WalletFlagSignDescription is set in order to sign the description
// text, otherwise it is ignored.
// Error is returned if given string does not pass the valid description check or an invalid wallet password was given.
func (w *Wallet)SetDescription(desc string, walletPassword *string) error {
	if err := CheckDescription(desc); err != nil {
		return err
	}

	if w.isFlagSet(WalletFlagSignDescription) {
		if sk := w.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
			w.desc = desc
			w.sign(sk)
		} else {
			return ErrorInvalidPassword
		}
	} else {
		w.desc = desc
	}

	return nil
}

// Derive ED25519 key for signing wallet entries.
func (w *Wallet)deriveSigningKey(key []byte) ed25519.PrivateKey {
	seed := w.decryptMasterSeed(key)
	defer EraseByteBuffer(seed)
	return ed25519.NewKeyFromSeed(seed)
}

func (w *Wallet)deriveSigningKeyPassword(walletPassword *string) ed25519.PrivateKey {
	if key := w.checkPassword(walletPassword); key != nil {
		defer EraseByteBuffer(key)
		return w.deriveSigningKey(key)
	} else {
		return nil
	}
}

// Create AES key from given password string
func deriveAesKey(password *string) (key []byte) {
	return pbkdf2.Key([]byte(*password), []byte("stellarwallet"), 4096, 32, sha1.New)
}

// AES encrypts data with given key.
// Data will be padded with random data to match AES block size.
// Enncrypted data is return in newly allocated slice. Input data will not be modified.
func aesEncrypt( data, key []byte) []byte {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	l := len(data)
	blockLen := block.BlockSize()

	blocks := l / blockLen

	padding :=  l % blockLen

	if padding != 0 {
		blocks += 1
	}

	buf := make([]byte, blockLen*blocks)

	if padding != 0 {
		// fill padding bytes with random numbers
		_, err = rand.Read(buf[blockLen*(blocks-1)+padding:])
		if err != nil {
			panic(err)
		}
	}

	copy(buf, data)

	itr := buf

	for i := 0; i < blocks; i++ {
		block.Encrypt(itr, itr)
		itr = itr[blockLen:]
	}

	return buf
} 

// AES descypts data with given key.
// Input data slice is overwritten by decrypted data.
func aesDecrypt( data, key []byte) {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}


	l := len(data)	
	blockLen := block.BlockSize()
	blocks := l / blockLen

	if l % blockLen != 0 {
		return
	}

	itr := data

	for i := 0; i < blocks; i++ {
		block.Decrypt(itr, itr)
		itr = itr[blockLen:]
	}
} 

// Adds a SHA1 checksum to data and encrypts it with given key.
func encryptWithCheckSum(data, key []byte) []byte {
	// build checksum using a hash
	mac := hmac.New(sha1.New, []byte(stellarwalletSeed))
	_, err := mac.Write(data)
	if err != nil {
		panic(err)
	}
	sum := mac.Sum(nil)

	dataChk := make([]byte, len(data))
	copy(dataChk, data)
	dataChk = append(dataChk, sum...)
	defer EraseByteBuffer(dataChk)

	enc := aesEncrypt(dataChk, key)

	return enc

}

// Decrypts data with given key and verifies SHA1 checksum.
// If verification fails nil is returned. Otherwise a newly
// allocated slice is returned containing the decrypted data.
// The input data is not modified.
 
func decryptWithCheckSum(encData []byte, resLen int, key []byte) []byte {
	buf := make([]byte, len(encData))
	copy(buf, encData)
	
	aesDecrypt(buf, key)

	if len(buf) < resLen {
		return nil
	}

	// check checksum using a hash
	mac := hmac.New(sha1.New, []byte(stellarwalletSeed))
	_, err := mac.Write(buf[:resLen])
	if err != nil {
		panic(err)
	}
	sum := mac.Sum(nil)

	if !hmac.Equal(sum, buf[resLen:resLen+mac.Size()]) {
		return nil
	}

	return buf[:resLen]
}

// Returns word list derived from stored master seed.
// key is used to decrypt the master seed.
func (w *Wallet)getBip39Mnemonic(key []byte) (words []string) {

	seed := w.decryptMasterSeed(key)

	if seed == nil {
		return
	}

	defer EraseByteBuffer(seed)
	
	wordString, err := bip39.NewMnemonic(seed)

	if err != nil {
		panic(err)
		return
	}

	words = strings.Split(wordString, " ")

	return
}

// Bip39Mnemonic returns mnemonic word list (24 words) associated with the current wallet.
// After creating a new wallet this word list should be presented to the user. 
func (w *Wallet)Bip39Mnemonic(walletPassword *string) (words []string) {

	key := deriveAesKey(walletPassword)

	defer EraseByteBuffer(key)

	words = w.getBip39Mnemonic(key)

	return
}

func (w *Wallet)encryptMasterSeed(seed, key []byte) {
	w.masterSeed = encryptWithCheckSum(seed, key)
}	

func (w *Wallet)decryptMasterSeed(key []byte) []byte {
	return decryptWithCheckSum(w.masterSeed, masterSeedLen, key)
}	

// Checks if given wallet password is valid.
// Returns derived AES key on success else nil
func (w *Wallet)checkPassword(walletPassword *string) []byte {
	if walletPassword == nil {
		return nil
	}

	key := deriveAesKey(walletPassword)

	seed := w.decryptMasterSeed(key)

	if seed != nil {
		EraseByteBuffer(seed)
		return key
	}

	return nil
}

// CheckPassword checks if given wallet password is valid.
func (w *Wallet)CheckPassword(walletPassword *string) bool {
	key := w.checkPassword(walletPassword)

	if key != nil {
		EraseByteBuffer(key)
		return true
	}

	return false
}



func (w *Wallet)encryptBip39Seed(seed, key []byte) {
	w.bip39Seed = encryptWithCheckSum(seed, key)
}	

func (w *Wallet)decryptBip39Seed(key []byte) []byte {
	return decryptWithCheckSum(w.bip39Seed, bip39SeedLen, key)
}	

func (w *Wallet)generateBip39Seed(key []byte, words []string , mnemonicPassword *string) bool {
	var seed, prevSeed []byte
	var err error

	mnemonic := strings.Join(words, " ")

	// paranoia mode: calculate seed 5 times and check for identical results
	// to reduce risk of generating an unreproducable seed caused by faulty hardware
	for i := 0 ; i < 5; i++ {
		prevSeed = seed
		seed, err = bip39.NewSeedWithErrorChecking(mnemonic, *mnemonicPassword)
		if err != nil {
			return false
		}

		if prevSeed != nil && bytes.Compare(prevSeed, seed) != 0 {
			panic("calculation error")
		}
	}	

	if len(seed) != bip39SeedLen {
		panic("Unexpected length of seed")
	}

	w.encryptBip39Seed(seed, key)

	return true
}

// GenerateBip39Seed generates the seed used for key derivation (generated accounts). This
// method mus be called before the first call to GenerateAccount().
// It uses the mnemonic word list, 
// which is internally derived from the master seed (same as returned by Bip39Mnemonic()),
// and combines it with the given mnemonic password. 
// The wallet password is required for decrypting and master seed and encrypting the generated
// key derivation seed (BIP39 seed). 
func (w *Wallet)GenerateBip39Seed(walletPassword *string, mnemonicPassword *string) bool {
	if w.bip39Seed != nil {
		return false
	}

	key := deriveAesKey(walletPassword)

	words := w.getBip39Mnemonic(key)

	if words == nil {
		// may happen if wallet password is not correct
		return false
	}


	return w.generateBip39Seed(key, words, mnemonicPassword)
}

// ChangePassword changes the wallet password. 
// false is returned only if the given wallet password is invalid.
func (w *Wallet)ChangePassword(password, newPassword *string) bool {
	key :=  w.checkPassword(password)
	if key == nil {
		return false
	}
	defer EraseByteBuffer(key)

	newKey := deriveAesKey(newPassword)
	defer EraseByteBuffer(newKey)

	masterSeed := w.decryptMasterSeed(key)
	if masterSeed == nil {
		panic("decrypting master seed failed")
	}
	defer EraseByteBuffer(masterSeed)

	var bip39Seed []byte

	if w.bip39Seed != nil {
		bip39Seed = w.decryptBip39Seed(key)
		if bip39Seed == nil {
			panic("decrypting bip39seed failed")
		}
		defer EraseByteBuffer(bip39Seed)
	}

	w.encryptMasterSeed(masterSeed, newKey)

	if bip39Seed != nil {
		w.encryptBip39Seed(bip39Seed, newKey)
	}

	for _, a := range w.accounts {
		if a.active && a.accountType == AccountTypeRandom {
			pkey := decryptAccountSeed(a.privateKey, key)
			if pkey == nil {
				panic("decrypting account seed failed")
			}
			a.privateKey = encryptAccountSeed(pkey, newKey)
			EraseByteBuffer(pkey)
		}
	}

	return true
}

func (w *Wallet)signAll(sk ed25519.PrivateKey) {
	w.sign(sk)

	for _, a := range w.accounts {
		a.sign(sk)
	}

	for _, a := range w.assets {
		a.sign(sk)
	}

	for _, tp := range w.tradingPairs {
		tp.sign(sk)
	}
}

func (w *Wallet)buildSigningData() []byte {
	d := make([]byte, 10, len(w.desc) + 10)

	binary.BigEndian.PutUint64(d[0:8], uint64(w.flags))
	binary.BigEndian.PutUint16(d[8:10], w.sep0005AccountCount)

	if w.isFlagSet(WalletFlagSignDescription) {
		d = append(d, w.desc...)
	}

	return d
}

func (w *Wallet)sign(sk ed25519.PrivateKey) {
	d := w.buildSigningData()
	w.signature = ed25519.Sign(sk, d)
}

func (w *Wallet)checkSignature(pk ed25519.PublicKey) bool {
	d := w.buildSigningData()
	return ed25519.Verify(pk, d, w.signature)
}

func (w *Wallet)newAccount() *Account {
	for _, a := range w.accounts {
		if !a.active {
			a.init(w)
			return a
		}
	}

	a := new(Account)
	a.init(w)

	w.accounts = append(w.accounts, a)

	return a
}

// GenerateAccount generates a new account according to SEP-0005. The wallet password
// is required to decrypt the BIP39 seed.
// Before this method can be used, method GenerateBip39Seed() must have been called before once.
// nil is returned if GenerateBip39Seed() was not called before or the wallet password is not valid.
func (w *Wallet)GenerateAccount(walletPassword *string) *Account {
	wkey := w.checkPassword(walletPassword)

	if wkey == nil {
		return nil
	}
	defer EraseByteBuffer(wkey)

	sk := w.deriveSigningKey(wkey)
	defer EraseByteBuffer(sk)

	return w.generateAccount(wkey, sk)
}

func (w *Wallet)generateAccount(wkey []byte, signingKey ed25519.PrivateKey) *Account {
	if w.bip39Seed == nil {
		return nil
	}

	seed := w.decryptBip39Seed(wkey)

	if seed == nil {
		return nil
	}
	defer EraseByteBuffer(seed)

	a := w.newAccount()

	p := fmt.Sprintf(derivation.StellarAccountPathFormat, w.sep0005AccountCount)

	var k, pk []byte
	var err error
	var key *derivation.Key

	for i := 0; i < 5; i++ {
		pk = k

		key, err = derivation.DeriveForPath(p, seed)
		if err != nil {
			panic(err)
		}

		k = key.Key

		if pk != nil && bytes.Compare(pk, k) != 0 {
			panic("calculation error")
		}
	}

	publicKey := derivePublicKey(key.Key)
	if err != nil {
		panic(err)
	}

	a.accountType = AccountTypeSEP0005
	a.sep0005DerivationPath = p
	a.publicKey, err = strkey.Encode(strkey.VersionByteAccountID, publicKey)

	if err != nil {
		panic(err)
	}

	a.sign(signingKey)
	a.active = true

	w.sep0005AccountCount++
	w.sign(signingKey)

	return a
}

func encryptAccountSeed(seed, key []byte) []byte {
	return encryptWithCheckSum(seed, key)
}

func decryptAccountSeed(encSeed, key []byte) []byte {
	return decryptWithCheckSum(encSeed, accountSeedLen, key)
}	

func derivePublicKey( seed []byte ) []byte {
	var prev, pub ed25519.PublicKey

	for i := 0; i < 5; i++ {
		prev = pub

		pub = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		
		if prev != nil && bytes.Compare(prev, pub) != 0 {
			panic("calculation error")
		}
	}
	return pub
}

// AddRandomAccount adds a new account with given private key (seed) and returns a new Account object.
// The private key is stored encrypted. 
// Application implementors should make the user aware that this type of account cannot be 
// recovered with the mnemonic word list and password.
// nil is returend if the wallet password is invalid or an invald seed string was provided.
func (w *Wallet)AddRandomAccount(seed *string, walletPassword *string) *Account {
	seedData, err := strkey.Decode(strkey.VersionByteSeed, *seed)
	if err != nil {
		return nil
	}
	defer EraseByteBuffer(seedData)

	key := w.checkPassword(walletPassword)

	if key == nil {
		return nil
	}
	defer EraseByteBuffer(key)

	sk := w.deriveSigningKey(key)
	defer EraseByteBuffer(sk)

	encSeed := encryptAccountSeed(seedData, key)

	pubKey := derivePublicKey(seedData)

	a := w.newAccount()

	a.accountType = AccountTypeRandom
	a.privateKey = encSeed
	a.publicKey, err = strkey.Encode(strkey.VersionByteAccountID, pubKey)

	if err != nil {
		panic(err)
	}

	a.sign(sk)
	a.active = true

	return a
}

// AddWatchingAccount adds a watching account and return a new Account object for it.
// Watching accounts just store the public account key.
// Watching accounts are treated as "own" accounts - in contrast to address book accounts.
// walletPassword is required only if public key signing is selected in the wallet flags, otherwise it is ignored.
// nil is returned if the given public key string is not valid or an invalid wallet password was given.
func (w *Wallet)AddWatchingAccount(pubkey string, walletPassword *string) *Account {

	if !CheckPublicKey(pubkey) {
		return nil
	}

	a := w.FindAccountByPublicKey(pubkey)

	if a != nil {
		return nil
	}

	var sk ed25519.PrivateKey

	if w.isFlagSet(WalletFlagSignAccounts) {
		if sk = w.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
		} else {
			return nil
		}
	}

	a = w.newAccount()

	a.accountType = AccountTypeWatching
	a.publicKey = pubkey

	a.sign(sk)

	a.active = true
	
	return a
}

// AddAddressBookAccount adds an address book account and return a new Account object for it.
// Address book accounts just store the public account key.
// Address book accounts are treated as "foreign" accounts - in contrast to watching accounts.
// walletPassword is required only if public key signing is selected in the wallet flags, otherwise it is ignored.
// nil is returned if the given public key string is not valid or an invalid wallet password was given.
func (w *Wallet)AddAddressBookAccount(pubkey string, walletPassword *string) *Account {

	if !CheckPublicKey(pubkey) {
		return nil
	}

	a := w.FindAccountByPublicKey(pubkey)

	if a != nil {
		return nil
	}

	var sk ed25519.PrivateKey

	if w.isFlagSet(WalletFlagSignAccounts) {
		if sk = w.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
		} else {
			return nil
		}
	}

	a = w.newAccount()

	a.accountType = AccountTypeAddressBook
	a.publicKey = pubkey

	a.sign(sk)

	a.active = true
	
	return a
}

// DeleteAccount deletes given account. false is returned if given account does not belong to current wallet object.
func (w *Wallet)DeleteAccount(acc *Account) bool {
	if acc.wallet == w {
		acc.active = false
		return true
	}

	return false
}

// FindAccountByPublicKey returns account object for given public account key.
// If not matching account is found, nil is returned.
func (w *Wallet)FindAccountByPublicKey(pubkey string) *Account {

	for _, a := range w.accounts {
		if a.active &&  a.publicKey == pubkey {
			return a
		}
	}

	return nil
}


// FindAccountByDescription returns first account matching given description string.
// Matching is performed case insensitive on sub string level..
// If not matching account is found, nil is returned.
func (w *Wallet)FindAccountByDescription(desc string) *Account {
	desc = strings.ToLower(desc)

	for _, a := range w.accounts {
		if a.active {
			if strings.Contains(strings.ToLower(a.desc), desc) {
				return a
			}
		}
	}

	return nil
}

// Accounts returns a slice containing all "own" accounts if current wallet, i.e.
// all but address book accounts.
func (w *Wallet)Accounts() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for _, a := range w.accounts {
		if a.active && a.IsOwnAccount() {
			accounts = append(accounts, a)
		}
	}

	return accounts
}

// SeedAccounts returns a slice containing all accounts with a private key,
// i.e. generated and random accounts.
func (w *Wallet)SeedAccounts() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for _, a := range w.accounts {
		if a.active && a.HasPrivateKey() {
			accounts = append(accounts, a)
		}
	}

	return accounts
}

// AddressBook returns a slice containing all address book accounts.
func (w *Wallet)AddressBook() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for _, a := range w.accounts {
		if a.active && a.IsAddressBookAccount() {
			accounts = append(accounts, a)
		}
	}

	return accounts
}

// Assets returns a slice containing all assets of current wallet.
func (w *Wallet)Assets() []*Asset {
	assets := make([]*Asset, 0, len(w.assets))

	for _, a := range w.assets {
		if a.active {
			assets = append(assets, a)
		}
	}

	return assets
}

// FindAsset returns asset object for given issues and asset id.
// nil is return if no matching asset is found.
func (w *Wallet)FindAsset(issuer, assetId string) *Asset {
	for _, a := range w.assets {
		if a.active && a.issuer == issuer && a.assetId == assetId {
			return a
		}
	}

	return nil
}

// FindAssetsByIssuer returns a slice containing all assets that match the given issuer string.
func (w *Wallet)FindAssetsByIssuer(issuer string) []*Asset {
	assets := make([]*Asset, 0, len(w.assets))

	for _, a := range w.assets {
		if a.active && a.issuer == issuer {
			assets = append(assets, a)
		}
	}

	return assets
}

func (w *Wallet)newAsset() *Asset {
	for _, a := range w.assets {
		if !a.active {
			a.init(w)
			return a
		}
	}

	a := &Asset{}
	a.tradingPairLink = list.New()
	a.init(w)

	w.assets = append(w.assets, a)

	return a
}

// AddAsset creates a new asset and returns a Asset object for it.
// walletPassword is required only if asset signing is selected in the wallet flags, otherwise it is ignored.
// nil is returned if the given issues string is not a valid public account key or
// if the given assetId is not valid.
func (w *Wallet)AddAsset(issuer, assetId string, walletPassword *string) *Asset {
	if !CheckPublicKey(issuer) {
		return nil
	}


	if CheckAssetId(assetId) != nil {
		return nil
	}


	a := w.FindAsset(issuer, assetId)
	if a != nil {
		return a
	}

	var sk ed25519.PrivateKey

	if w.isFlagSet(WalletFlagSignAssets) {
		if sk = w.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
		} else {
			return nil
		}
	}

	a = w.newAsset()

	a.issuer = issuer
	a.assetId = assetId
	a.sign(sk)
	a.active = true

	return a
}	

// DeleteAsset deletes given asset from wallet.
// Returns true on success. 	
func (w *Wallet)DeleteAsset(a *Asset) bool {
	if a.wallet != w {
		return false
	}

	if a.tradingPairLink.Len() != 0 {
		return false
	}

	a.active = false
	return true
}


// Trading Pairs

func (w *Wallet)newTradingPair() *TradingPair {
	for _, tp := range w.tradingPairs {
		if !tp.active {
			tp.init(w)
			return tp
		}
	}

	tp := &TradingPair{}
	tp.init(w)

	w.tradingPairs = append(w.tradingPairs, tp)

	return tp
}

// FindTradingPair returns trading pair for given assets. Return nil of no trading pair is defined for given assets.
func (w *Wallet)FindTradingPair(asset1, asset2 *Asset) *TradingPair {
	for _, tp := range w.tradingPairs {
		if tp.asset1 == asset1 && tp.asset2 == asset2 {
			return tp
		}
	}

	return nil
} 

// AddTradingPair adds a new trading pair to the wallet. If a trading pair for the given assets is already defined, the existing pair is returned.
// The native Lumen is represented by a nil asset.
// walletPassword is required only if asset signing is selected in the wallet flags, otherwise it is ignored.
// For following error conditions nil is returned: assets do not belong to current wallet, assets are identical,
// invalid wallet password
func (w *Wallet)AddTradingPair(asset1, asset2 *Asset, walletPassword *string) *TradingPair {
	if asset1 != nil && asset1.wallet != w {
		return nil
	}

	if asset2 != nil && asset2.wallet != w {
		return nil
	}

	if asset1 == asset2 {
		return nil
	}

	tp := w.FindTradingPair(asset1, asset2)

	if tp != nil {
		return tp
	}

	var sk ed25519.PrivateKey

	if w.isFlagSet(WalletFlagSignTradingPairs) {
		if sk = w.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
		} else {
			return nil
		}
	}


	tp = w.newTradingPair()

	tp.active = true
	tp.asset1 = asset1
	tp.asset2 = asset2

	if asset1 != nil {
		asset1.linkTradingPair(tp)
	}

	if asset2 != nil {
		asset2.linkTradingPair(tp)
	}

	tp.sign(sk)

	return tp
}

// DeleteTradingPair deletes given tarding pair from the wallet.
// On success true is returned.
func (w *Wallet)DeleteTradingPair(tp *TradingPair) bool {
	if tp.wallet != w {
		return false
	}

	if tp.asset1 != nil {
		tp.asset1.unlinkTradingPair(tp)
	}

	if tp.asset2 != nil {
		tp.asset2.unlinkTradingPair(tp)
	}

	tp.active = false

	return true
}

// TradingPairs returns a slice with all trading pairs of the wallet.
func (w *Wallet)TradingPairs() []*TradingPair {
	tps := make([]*TradingPair, 0, len(w.tradingPairs))

	for _, tp := range w.tradingPairs {
		if tp.active {
			tps = append(tps, tp)
		}
	}
	
	return tps
}

func (a *Account)init(wallet *Wallet) {
	a.wallet = wallet
	a.accountType = AccountTypeUndefined
	a.desc = ""
	a.publicKey = ""
	a.privateKey = nil
	a.sep0005DerivationPath = ""
	a.memoText = ""
	a.memoId = 0
	a.memoIdSet = false
	a.signature = nil
}

func (a* Account)checkConsistency(key []byte) bool {
	if !CheckPublicKey(a.publicKey) {
		return false
	}

	switch a.accountType {
	case AccountTypeSEP0005:
		seed := a.wallet.decryptBip39Seed(key)
		defer EraseByteBuffer(seed)

		aseed, err := derivation.DeriveForPath(a.sep0005DerivationPath, seed)

		if aseed != nil {
			defer EraseByteBuffer(aseed.Key)
		}

		if aseed != nil && err == nil {
			publicKey := derivePublicKey(aseed.Key)
			s, _ := strkey.Encode(strkey.VersionByteAccountID, publicKey)
			if a.publicKey == s {
				return true
			}
		}

	case AccountTypeRandom:
		aseed := decryptAccountSeed(a.privateKey, key)
		if aseed != nil {
			defer EraseByteBuffer(aseed)
			publicKey := derivePublicKey(aseed)
			s, _ := strkey.Encode(strkey.VersionByteAccountID, publicKey)
			if a.publicKey == s {
				return true
			}
		}
	case AccountTypeWatching:
		if a.privateKey == nil && a.sep0005DerivationPath == "" {
			return true
		}

	case AccountTypeAddressBook:
		if a.privateKey == nil && a.sep0005DerivationPath == "" {
			return true
		}
	}

	return false
}

func (a *Account)isSigned() bool {
	return a.wallet.isFlagSet(WalletFlagSignAccounts)
}

func (a *Account)buildSigningData() []byte {

	if a.isSigned() {

		d := make([]byte, 2, len(a.desc)+len(a.memoText)+100)

		binary.BigEndian.PutUint16(d[0:2], a.accountType)
		d = append(d, a.publicKey...)

		if a.accountType == AccountTypeSEP0005 {
			d = append(d, a.sep0005DerivationPath...)
		} else {
			d = append(d, 0)
		}

		if a.wallet.isFlagSet(WalletFlagSignAccountMemo) {
			d = append(d, a.memoText...)
			d = append(d, 0)
			if a.memoIdSet {
				buf := make([]byte, 8)
				binary.BigEndian.PutUint64(buf, a.memoId)
				d = append(d, buf...)
			} else {
				d = append(d, 0)
			}
		} else {
			d = append(d, 0)
		}

		if a.wallet.isFlagSet(WalletFlagSignDescription) {
			d = append(d, a.desc...)
			d = append(d, 0)
		} else {
			d = append(d, 0)
		}

		return d
	}

	return nil
}

func (a *Account)sign(sk ed25519.PrivateKey) {
	if sk == nil {
		a.signature = nil
		return
	}

	d := a.buildSigningData()
	if d != nil {
		a.signature = ed25519.Sign(sk, d)
	} else {
		a.signature = nil
	}
}

func (a *Account)checkSignature(vk ed25519.PublicKey) bool {
	d := a.buildSigningData()
	if d == nil {
		return true
	}

	if a.signature == nil {
		return false
	}

	return ed25519.Verify(vk, d, a.signature)
}

// Type returns account type.
func (a *Account)Type() uint16 {
	return a.accountType
}

// IsOwnAccount checks if current account is an own account, i.e. of type generated, random or watching.
func (a *Account)IsOwnAccount() bool {
	switch a.accountType {
	case AccountTypeSEP0005:
		return true
	case AccountTypeRandom:
		return true
	case AccountTypeWatching:
		return true
	}

	return false
}

// IsAddressBookAccount checks if current account is an address book account..
func (a *Account)IsAddressBookAccount() bool {
	if a.accountType == AccountTypeAddressBook {
		return true
	}

	return false
}

// HasPrivateKey checks true if current account holds a private key.
func (a *Account)HasPrivateKey() bool {
	switch a.accountType {
	case AccountTypeSEP0005:
		return true
	case AccountTypeRandom:
		return true
	}

	return false
}




// Description returns description of account. Empty string is returned if no description is defined.
func (a *Account)Description() string {
	return a.desc
}

// SetDescription sets description on account.
// walletPassword is required only if account and description signing is selected in the wallet flags, otherwise
// it is ignored.
// Error is returned if given string does not pass the valid description check or an invalid wallet password was given.
func (a *Account)SetDescription(desc string, walletPassword *string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	if a.isSigned() && a.wallet.isFlagSet(WalletFlagSignDescription) {
		if sk := a.wallet.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
			a.desc = desc
			a.sign(sk)
		} else {
			return ErrorInvalidPassword
		}
	} else {
		a.desc = desc
	}

	return nil
}

// MemoText returns the optional memo text of account. Empty string is returned if no memo text is defined.
func (a *Account)MemoText() string {
	return a.memoText
}

// SetMemoText sets memo text on account.
// walletPassword is required only if account and memo signing is selected in the wallet flags, otherwise
// it is ignored.
// Error is returned if the given memo string is not valid or an invalid wallet password was given.

func (a *Account)SetMemoText(memo string, walletPassword *string) error {
	err := CheckMemoText(memo)
	if err != nil {
		return err
	}

	if a.isSigned() && a.wallet.isFlagSet(WalletFlagSignAccountMemo) {
		if sk := a.wallet.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
			a.memoText = memo
			a.sign(sk)
		} else {
			return ErrorInvalidPassword
		}
	} else {
		a.memoText = memo
	}

	return nil
}

// MemoId returns memo id of account. If no memo id is defined for current account, the boolean return value is false.
func (a *Account)MemoId() (bool, uint64) {
	if a.memoIdSet {
		return true, a.memoId
	}

	return false, 0
}

// SetMemoId sets memo id on account.
// walletPassword is required only if account and memo signing is selected in the wallet flags, otherwise
// it is ignored.
// Error is returned if an invalid wallet password was given.
func (a *Account)SetMemoId(memo uint64, walletPassword *string) error {
	if a.isSigned() && a.wallet.isFlagSet(WalletFlagSignAccountMemo) {
		if sk := a.wallet.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
			a.memoId = memo
			a.memoIdSet = true
			a.sign(sk)
		} else {
			return ErrorInvalidPassword
		}
	} else {
		a.memoId = memo
		a.memoIdSet = true
	}

	return nil
}

// ClearMemoId clears memo id from account.
// walletPassword is required only if account and memo signing is selected in the wallet flags, otherwise
// it is ignored.
// Error is returned if an invalid wallet password was given.
func (a *Account)ClearMemoId(walletPassword *string) error {
	if a.isSigned() && a.wallet.isFlagSet(WalletFlagSignAccountMemo) {
		if sk := a.wallet.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
			a.memoId = 0
			a.memoIdSet = false
			a.sign(sk)
		} else {
			return ErrorInvalidPassword
		}
	} else {
		a.memoId = 0
		a.memoIdSet = false
	}

	return nil
}

// PublicKey returns public key of account.
func (a *Account)PublicKey() string {
	if !a.active {
		panic("account not active")
	}
	return a.publicKey
}

// PrivateKey returns private key of account.
// Emptry string is returned if wallet password is not valid or current account does not hold a private key.
func (a *Account)PrivateKey(walletPassword *string) string {
	wkey := a.wallet.checkPassword(walletPassword)

	if wkey == nil {
		return ""
	}

	defer EraseByteBuffer(wkey)

	switch a.accountType {
	case AccountTypeSEP0005:
		seed := a.wallet.decryptBip39Seed(wkey)
		if seed == nil {
			return ""
		}
		defer EraseByteBuffer(seed)
		key, err := derivation.DeriveForPath(a.sep0005DerivationPath, seed)
		if err != nil {
			return ""
		}
		s, err := strkey.Encode(strkey.VersionByteSeed, key.Key)
		if err != nil {
			return ""
		}
		return s

	case AccountTypeRandom:
		seed := decryptAccountSeed(a.privateKey, wkey)
		if seed == nil {
			panic("private key decryption failed")
		}
		defer EraseByteBuffer(seed)
		s, err := strkey.Encode(strkey.VersionByteSeed, seed)
		if err != nil {
			panic(err)
		}
		return s
	}

	return ""
}

func (a *Asset)init(wallet *Wallet) {
	a.wallet = wallet
	a.tradingPairLink.Init()
	a.desc = ""
	a.issuer = ""
	a.assetId = ""
	a.signature = nil
}

func (a *Asset)isSigned() bool {
	return a.wallet.isFlagSet(WalletFlagSignAssets)
}

func (a *Asset)checkConsistency() bool {
	if !CheckPublicKey(a.issuer) {
		return false
	}

	if CheckAssetId(a.assetId) != nil {
		return false
	}

	return true
}

func (a *Asset)buildSigningData() []byte {

	if a.isSigned() {
		d := make([]byte, 0, len(a.issuer)+len(a.assetId)+len(a.desc)+10)

		d = append(d, a.issuer...)
		d = append(d, a.assetId...)

		if a.wallet.isFlagSet(WalletFlagSignDescription) {
			d = append(d, a.desc...)
		}
		d = append(d, 0)

		return d
	}

	return nil
}

func (a *Asset)sign(sk ed25519.PrivateKey) {
	d := a.buildSigningData()
	if d != nil {
		a.signature = ed25519.Sign(sk, d)
	} else {
		a.signature = nil
	}
}

func (a *Asset)checkSignature(vk ed25519.PublicKey) bool {
	d := a.buildSigningData()

	if d == nil {
		return true
	}

	if a.signature == nil {
		return false
	}

	return ed25519.Verify(vk, d, a.signature)
}

func (a *Asset)linkTradingPair(tp *TradingPair) {
	for itr := a.tradingPairLink.Front(); itr != nil; itr = itr.Next() {
		if itr.Value == tp {
			return
		}
	}

	a.tradingPairLink.PushBack(tp)
}

func (a *Asset)unlinkTradingPair(tp *TradingPair) {
	for itr := a.tradingPairLink.Front(); itr != nil; itr = itr.Next() {
		if itr.Value == tp {
			a.tradingPairLink.Remove(itr)
			return
		}
	}
}

// TradingPairs returns slice with all trading pairs the refer to the current asset.
func (a *Asset)TradingPairs() []*TradingPair {
	tps := make([]*TradingPair, 0, a.tradingPairLink.Len())

	for itr := a.tradingPairLink.Front(); itr != nil; itr = itr.Next() {
		tps = append(tps, itr.Value.(*TradingPair))
	}
	
	return tps
}

// Description returns description of asset. Empty string is returned if no description is defined.
func (a *Asset)Description() string {
	return a.desc
}

// SetDescription sets description on asset.
// walletPassword is required only if asset and description signing is selected in the wallet flags, otherwise
// it is ignored.
// Error is returned if given string does not pass the valid description check or an invalid wallet password was given.
func (a *Asset)SetDescription(desc string, walletPassword *string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	if a.isSigned() && a.wallet.isFlagSet(WalletFlagSignDescription) {
		if sk := a.wallet.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
			a.desc = desc
			a.sign(sk)
		} else {
			return ErrorInvalidPassword
		}
	} else {
		a.desc = desc
	}

	return nil
}

// Returns issuer of asset.
func (a *Asset)Issuer() string {
	return a.issuer
}

// Returns asset ID (aka code). 
func (a *Asset)AssetId() string {
	return a.assetId
}

func (tp *TradingPair)init(wallet *Wallet) {
	tp.wallet = wallet
	tp.desc = ""
	tp.asset1 = nil
	tp.asset2 = nil
	tp.signature = nil
}

func (tp *TradingPair)checkConsistency() bool {
	if tp.asset1 == tp.asset2 {
		return false
	}

	if tp.asset1 != nil && tp.asset1.wallet != tp.wallet {
		return false
	}

	if tp.asset2 != nil && tp.asset2.wallet != tp.wallet {
		return false
	}

	return true
}

func (tp *TradingPair)isSigned() bool {
	return tp.wallet.isFlagSet(WalletFlagSignTradingPairs)
}

func (tp *TradingPair)buildSigningData() []byte {

	if tp.isSigned() {
		xlm := "xlm"
		d := make([]byte, 0, 200)

		if tp.asset1 != nil {
			d = append(d, tp.asset1.issuer...)
			d = append(d, tp.asset1.assetId...)
			d = append(d, 0)
		} else {
			d = append(d, xlm...)
			d = append(d, 0)
		}

		if tp.asset2 != nil {
			d = append(d, tp.asset2.issuer...)
			d = append(d, tp.asset2.assetId...)
			d = append(d, 0)
		} else {
			d = append(d, xlm...)
			d = append(d, 0)
		}

		if tp.wallet.isFlagSet(WalletFlagSignDescription) {
			d = append(d, tp.desc...)
			d = append(d, 0)
		}

		return d
	}

	return nil
}

func (tp *TradingPair)sign(sk ed25519.PrivateKey) {
	d := tp.buildSigningData()
	if d != nil {
		tp.signature = ed25519.Sign(sk, d)
	} else {
		tp.signature = nil
	}
}

func (tp *TradingPair)checkSignature(vk ed25519.PublicKey) bool {
	d := tp.buildSigningData()
	if d == nil {
		return true
	}

	if tp.signature == nil {
		return false
	}

	return ed25519.Verify(vk, d, tp.signature)
}

// Description returns description of trading pair. Empty string is returned if no description is defined.
func (tp *TradingPair)Description() string {
	return tp.desc
}

// SetDescription sets description on tarding pair.
// walletPassword is required only if trading pair and description signing is selected in the wallet flags, otherwise
// it is ignored.
// Error is returned if given string does not pass the valid description check or an invalid wallet password was given.
func (tp *TradingPair)SetDescription(desc string, walletPassword *string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	if tp.isSigned() && tp.wallet.isFlagSet(WalletFlagSignDescription) {
		if sk := tp.wallet.deriveSigningKeyPassword(walletPassword); sk != nil {
			defer EraseByteBuffer(sk)
			tp.desc = desc
			tp.sign(sk)
		} else {
			return ErrorInvalidPassword
		}
	} else {
		tp.desc = desc
	}

	return nil
}

// Asset1 returns first asset of trading pair. nil denotes native Lumen.
func (tp *TradingPair)Asset1() *Asset {
	return tp.asset1
}

// Asset2 returns second asset of trading pair. nil denotes native Lumen.
func (tp *TradingPair)Asset2() *Asset {
	return tp.asset2
}


// SelfTest performs self test to ensure that hardware performs correct calculations.
// Failures are indicated by a non nil error. 
// All wallet creation methods run this self test as well and will panic if it fails.
// This function should be called by an application first in order to gracefully handle 
// hardware failures.
func SelfTest() error {
	if gSelfTestDone {
		return gSelfTestStatus
	}

	gSelfTestDone = true
	gSelfTestStatus = nil

	errPrefix := "stellarwallet self test: "

	mnwords := "cable spray genius state float twenty onion head street palace net private method loan turn phrase state blanket interest dry amazing dress blast tube"
	w := strings.Split(mnwords, " ")

	mnPw := "p4ssphr4se"
	wPw := "gBCdqqYVvCmJJAQOhtuwme8vvGArKDov"

	wallet := NewWalletFromMnemonic(WalletFlagSignDescription|WalletFlagSignAccounts, &wPw, w, &mnPw)

	if wallet == nil {
		gSelfTestStatus = errors.New(errPrefix+"wallet creation from mnemonic seed failed")
		return gSelfTestStatus
	}

	// verify seed generation according to SEP-0005 and decryption of seed
	// patterns from: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
	expectedKeys := []string{
		"GDAHPZ2NSYIIHZXM56Y36SBVTV5QKFIZGYMMBHOU53ETUSWTP62B63EQ", "SAFWTGXVS7ELMNCXELFWCFZOPMHUZ5LXNBGUVRCY3FHLFPXK4QPXYP2X",
		"GDY47CJARRHHL66JH3RJURDYXAMIQ5DMXZLP3TDAUJ6IN2GUOFX4OJOC", "SBQPDFUGLMWJYEYXFRM5TQX3AX2BR47WKI4FDS7EJQUSEUUVY72MZPJF",
		"GCLAQF5H5LGJ2A6ACOMNEHSWYDJ3VKVBUBHDWFGRBEPAVZ56L4D7JJID", "SAF2LXRW6FOSVQNC4HHIIDURZL4SCGCG7UEGG23ZQG6Q2DKIGMPZV6BZ",
		"GBC36J4KG7ZSIQ5UOSJFQNUP4IBRN6LVUFAHQWT2ODEQ7Y3ASWC5ZN3B", "SDCCVBIYZDMXOR4VPC3IYMIPODNEDZCS44LDN7B5ZWECIE57N3BTV4GQ",
		"GA6NHA4KPH5LFYD6LZH35SIX3DU5CWU3GX6GCKPJPPTQCCQPP627E3CB", "SA5TRXTO7BG2Z6QTQT3O2LC7A7DLZZ2RBTGUNCTG346PLVSSHXPNDVNT",
		"GBOWMXTLABFNEWO34UJNSJJNVEF6ESLCNNS36S5SX46UZT2MNYJOLA5L", "SDEOED2KPHV355YNOLLDLVQB7HDPQVIGKXCAJMA3HTM4325ZHFZSKKUC",
		"GBL3F5JUZN3SQKZ7SL4XSXEJI2SNSVGO6WZWNJLG666WOJHNDDLEXTSZ", "SDYNO6TLFNV3IM6THLNGUG5FII4ET2H7NH3KCT6OAHIUSHKR4XBEEI6A",
		"GA5XPPWXL22HFFL5K5CE37CEPUHXYGSP3NNWGM6IK6K4C3EFHZFKSAND", "SDXMJXAY45W3WEFWMYEPLPIF4CXAD5ECQ37XKMGY5EKLM472SSRJXCYD",
		"GDS5I7L7LWFUVSYVAOHXJET2565MGGHJ4VHGVJXIKVKNO5D4JWXIZ3XU", "SAIZA26BUP55TDCJ4U7I2MSQEAJDPDSZSBKBPWQTD5OQZQSJAGNN2IQB",
		"GBOSMFQYKWFDHJWCMCZSMGUMWCZOM4KFMXXS64INDHVCJ2A2JAABCYRR", "SDXDYPDNRMGOF25AWYYKPHFAD3M54IT7LCLG7RWTGR3TS32A4HTUXNOS"}

	for i := 0; i < len(expectedKeys)/2; i++ {
		a := wallet.GenerateAccount(&wPw)

		if a.PublicKey() != expectedKeys[2*i] {
			gSelfTestStatus = errors.New(errPrefix+"invalid public key generated")
			return gSelfTestStatus
		}
		if a.PrivateKey(&wPw)!= expectedKeys[2*i+1] {
			gSelfTestStatus = errors.New(errPrefix+"invalid seed generated")
			return gSelfTestStatus
		}

	}

	// verify derivation of public keys from given seeds and en-/decryption of seeds
	expectedKeys = []string{
		"GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", "SAEWIVK3VLNEJ3WEJRZXQGDAS5NVG2BYSYDFRSH4GKVTS5RXNVED5AX7",
		"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", "SBKSABCPDWXDFSZISAVJ5XKVIEWV4M5O3KBRRLSPY3COQI7ZP423FYB4",
		"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", "SD5CCQAFRIPB3BWBHQYQ5SC66IB2AVMFNWWPBYGSUXVRZNCIRJ7IHESQ",
		"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", "SBSGSAIKEF7JYQWQSGXKB4SRHNSKDXTEI33WZDRR6UHYQCQ5I6ZGZQPK",
		"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", "SBIZH53PIRFTPI73JG7QYA3YAINOAT2XMNAUARB3QOWWVZVBAROHGXWM",
		"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", "SCVM6ZNVRUOP4NMCMMKLTVBEMAF2THIOMHPYSSMPCD2ZU7VDPARQQ6OY",
		"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "SBSHUZQNC45IAIRSAHMWJEJ35RY7YNW6SMOEBZHTMMG64NKV7Y52ZEO2",
		"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", "SC2QO2K2B4EBNBJMBZIKOYSHEX4EZAZNIF4UNLH63AQYV6BE7SMYWC6E",
		"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", "SCGMC5AHAAVB3D4JXQPCORWW37T44XJZUNPEMLRW6DCOEARY3H5MAQST",
		"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", "SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF",
		"GAOOWGZIMGN3HGKMAX4WLCEDUEBWLZWCJVCXEJN7BB4BREJ6N3PFA5HZ", "SAFI4KRSMSW7OF5UCN47NCWINORPNHHJZJEAKF7DBI7IIACUKZFVT3UR",
		"GBIKJJORC7APJRDRVX2RCBDMUCCK73U6JXSQL4T7AHT7GRTY73KTS5MZ", "SDA4QBYTQFXP2CWUSBBEX22RWQAYIJEBQSAO6QNO4LASTFE2JCVUVROJ",
		"GBCKQ4CHJF3OPKSJQD6G7NBSGMMQ5HDD77ZIKDIREBFBFCRMHJIOELLM", "SCPISHJZ6E5TN6J2OFLIKJ26UTQRDNTT2VJHDJIKD4LWQMKUTAQAG6UV"}



	for i := 0; i < len(expectedKeys)/2; i++ {
		a := wallet.AddRandomAccount(&expectedKeys[2*i+1], &wPw)

		if a.PublicKey() != expectedKeys[2*i] {
			gSelfTestStatus = errors.New(errPrefix+"invalid public key generated")
			return gSelfTestStatus
		}
		if a.PrivateKey(&wPw)!= expectedKeys[2*i+1] {
			gSelfTestStatus = errors.New(errPrefix+"invalid seed returned")
			return gSelfTestStatus
		}
	}

	return nil
}
