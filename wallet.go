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

)


const stellarwalletSeed = "sellarwallet seed"

const masterSeedLen = 32
const bip39SeedLen = 64
const accountSeedLen = 32

const AccountTypeUndefined = 0 // Account type undefined
const AccountTypeSEP0005 = 1 // Account is SEP0005 derived from the BIP39 seed
const AccountTypeRandom = 2  // Account is based on a randomly generated key
const AccountTypeWatching = 3 // Account has a public key only 
const AccountTypeAddressBook = 4 // Account is an address book entry (public key only) 


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
}

type Asset struct {
	wallet *Wallet
	active bool
	tradingPairLink *list.List

	desc string
	issuer string
	assetId string
}	

type TradingPair struct {
	wallet *Wallet
	active bool

	desc string
	asset1 *Asset
	asset2 *Asset
}

type Wallet struct {
	desc string

	masterSeed []byte

	bip39Seed []byte

	sep0005AccountCount uint16

	accounts []Account
	assets []*Asset
	tradingPairs []*TradingPair
}

var (
	g_selfTestDone = false
	g_selfTestStatus error

)

// Erases content of given byte buffer.
func EraseByteBuffer(b []byte) {
	if b != nil {
		for i, _ := range b {
			b[i] = 0
		}
	}
}

// Erases content of given string.
func EraseString(s *string) {
	EraseByteBuffer([]byte(*s))
}

// Checks for valid wallet, account or asset description string.
// If given description is not valid returned error contains details about failed check.
func CheckDescription(s string) error {
	if len(s) > 2000 {
		return errors.New("exceeds max length (2000 characters)")
	}

	return nil
}

// Checks for valid transaction memo text. 
// If given memo text is not valid returned error contains details about failed check.
func CheckMemoText(s string) error {
	if len(s) > 28 {
		return errors.New("exceeds max length (28 characters)")
	}

	return nil
}

// Checks if given string is a valid public account key.
func CheckPublicKey(s string) bool {
	_, err := strkey.Decode(strkey.VersionByteAccountID, s)

	if err != nil {
		return false
	}

	return true
}

// Checks if given string is a valid private account key (seed).
func CheckPrivateKey(s *string) bool {
	_, err := strkey.Decode(strkey.VersionByteSeed, *s)

	if err != nil {
		return false
	}

	return true

}

// Checks if given string is a valid asset id. 
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

// Checks if given string is a valid mnemonic word.
// Can be used by applications to immediately check validity of entered mnemonic words for wallet recovery.
func CheckMnemonicWord(s string) bool {
	_, found := bip39.ReverseWordMap[s]

	return found
}

// Create a new empty wallet, encrypted with given password.
// Each new wallet has an associated encrypted 256 bit entropy, which is the source for the mnemonic words list,
// i.e. the mnemonic word list is defined when a new wallet is created.
// This method panics if the build-in self test fails (see method SelfTest()).
func NewWallet(password *string) *Wallet {
	if err := SelfTest(); err != nil {
		panic(err.Error())
	}

	wallet := new(Wallet)

	entropy, err := bip39.NewEntropy(256)
	
	if err != nil {
		panic(err)
	}
	
	key := deriveAesKey(password)

	wallet.encryptMasterSeed(entropy, key)

	EraseByteBuffer(entropy)
	EraseByteBuffer(key)
	
	return wallet
}

// Creates a new wallet from a given mnemonic word list and mnemonic password and encrypts it with given wallet password.
// This method is used to recover a wallet from a mnemonic word list and password.
// If the mnemonic word list is invalid, nil will be returned.
// An invalid mnemonic password is not detected so that it cannot be reported to the user. If a wrong mnemonic password is provided,
// another set of account seeds will be generated and the user will not see his funds.  
// This method panics if the build-in self test fails (see method SelfTest()).
func NewWalletFromMnemonic(walletPassword *string, mnemonic []string, mnemonicPassword *string) *Wallet {
	if err := SelfTest(); err != nil {
		panic(err.Error())
	}

	w := new(Wallet)

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

	return w
}


// This function can be used to recover accounts after a wallet was recovered from
// a mnemonic word list. It will generate accounts and check if they are funded
// via provided function fundedCheck(). fundedCheck() must be a functions that
// checks on the Stellar network if the given account is funded and returns true in case.
// maxGap defines the maximum number of unfunded accounts being accepted until the search stops.
 
func (w *Wallet) RecoverAccounts(walletPassword *string, maxGap uint16, fundedCheck func (adr string) bool) {

	var lastFound = w.sep0005AccountCount

	for {
		a := w.GenerateSep0005Account(walletPassword)
		if a == nil {
			// can happen if invalid wallet password is provided
			return
		}

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
}

// Creates a new wallet from an exported binary serialization of the wallet content.
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

// Creates a new wallet from an exported ascii (base 64) serialization of the wallet content.
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

// Creates a binary serialization of the wallet content, e.g. for permanent storage of the wallet on disk.
func (w *Wallet)ExportBinary() []byte {
	return w.writeToBufferCompressed()
}

// Creates an ascii (base 64) serialization of the wallet content, e.g. for permanent storage of the wallet on disk.
func (w *Wallet)ExportBase64() string {
	buf := w.writeToBufferCompressed()

	if buf == nil {
		return ""
	} else {
		return base64.StdEncoding.EncodeToString(buf)
	}
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

// Returns optional wallet description.
func (w *Wallet)GetDescription() string {
	return w.desc
}

// Sets wallet description. Error is returned if given string does not pass description check.
func (w *Wallet)SetDescription(desc string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	w.desc = desc

	return nil
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

// Returns mnemonic word list (24 words) associated with the current wallet.
// After creating a new wallet this word list should be presented to the user. 
func (w *Wallet)GetBip39Mnemonic(walletPassword *string) (words []string) {

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
	key := deriveAesKey(walletPassword)

	seed := w.decryptMasterSeed(key)

	if seed != nil {
		EraseByteBuffer(seed)
		return key
	}

	return nil
}

// Checks if given wallet password is valid.
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

// Generate the seed used for key derivation (generated accounts). This
// method mus be called before the first call to GenerateSep0005Account().
// It uses the mnemonic word list, 
// which is internally derived from the master seed (same as returned by GetBip39Mnemonic()),
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

// Changes the wallet password. 
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

	for i, _ := range w.accounts {
		a := &w.accounts[i]

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

func (w *Wallet)newAccount() *Account {
	for i, _ := range w.accounts {
		a := &w.accounts[i]
		if !a.active {
			a.init(w)
			return a
		}
	}

	w.accounts = append(w.accounts, Account{})

	a := &w.accounts[len(w.accounts)-1]

	a.init(w)

	return a
}

// Generates a new account based on the stored BIP39 seed. The wallet password
// is required to decrypt the BIP39 seed.
// Before this method can be used, method GenerateBip39Seed() must have been called before once.
// nil is returned if GenerateBip39Seed() was not called before or the wallet password is not valid.
func (w *Wallet)GenerateSep0005Account(walletPassword *string) *Account {
	if w.bip39Seed == nil {
		return nil
	}

	wkey := w.checkPassword(walletPassword)

	if wkey == nil {
		return nil
	}
	defer EraseByteBuffer(wkey)
	
	seed := w.decryptBip39Seed(wkey)

	if seed == nil {
		return nil
	}
	defer EraseByteBuffer(seed)

	a := w.newAccount()

	p := fmt.Sprintf(derivation.StellarAccountPathFormat, w.sep0005AccountCount)

	w.sep0005AccountCount++

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

	a.active = true

	return a
}

func encryptAccountSeed(seed, key []byte) []byte {
	return encryptWithCheckSum(seed, key)
}

func decryptAccountSeed(encSeed, key []byte) []byte {
	return decryptWithCheckSum(encSeed, accountSeedLen, key)
}	

func derivePublicKey( seed []byte ) []byte {
	var prev, pub []byte
	var err error

	for i := 0; i < 5; i++ {
		prev = pub

		reader := bytes.NewReader(seed)
		pub, _, err = ed25519.GenerateKey(reader)
		if err != nil {
			panic(err)
		}

		if prev != nil && bytes.Compare(prev, pub) != 0 {
			panic("calculation error")
		}
	}
	return pub
}

// Adds a new account with given private key (seed) and returns a new Account object.
// The private key is stored encrypted. 
// Application implementors should make the user aware that this type of account cannot be 
// recovered with the mnemonic word list and password.
// nil is returend if the wallet password is invalid or an invald seed string was provided.
func (w *Wallet)AddRandomAccount(seed *string, walletPassword *string) *Account {
	key := w.checkPassword(walletPassword)

	if key == nil {
		return nil
	}
	defer EraseByteBuffer(key)
	
	seedData, err := strkey.Decode(strkey.VersionByteSeed, *seed)
	if err != nil {
		return nil
	}
	defer EraseByteBuffer(seedData)

	encSeed := encryptAccountSeed(seedData, key)

	pubKey := derivePublicKey(seedData)

	a := w.newAccount()

	a.accountType = AccountTypeRandom
	a.privateKey = encSeed
	a.publicKey, err = strkey.Encode(strkey.VersionByteAccountID, pubKey)

	if err != nil {
		panic(err)
	}

	a.active = true

	return a
}

// Adds a watching account and return a new Account object for it.
// Watching accounts just store the public account key.
// Watching accounts are treated as "own" accounts - in contrast to address book accounts.
// nil is returned if the given public key string is not valid.
func (w *Wallet)AddWatchingAccount(pubkey string) *Account {

	if !CheckPublicKey(pubkey) {
		return nil
	}

	a := w.FindAccountByPublicKey(pubkey)

	if a != nil {
		return nil
	}

	a = w.newAccount()

	a.accountType = AccountTypeWatching
	a.publicKey = pubkey

	a.active = true
	
	return a
}

// Adds an address book account and return a new Account object for it.
// Address book accounts just store the public account key.
// Address book accounts are treated as "foreign" accounts - in contrast to watching accounts.
// nil is returned if the given public key string is not valid.
func (w *Wallet)AddAddressBookAccount(pubkey string) *Account {

	if !CheckPublicKey(pubkey) {
		return nil
	}

	a := w.FindAccountByPublicKey(pubkey)

	if a != nil {
		return nil
	}

	a = w.newAccount()

	a.accountType = AccountTypeAddressBook
	a.publicKey = pubkey

	a.active = true
	
	return a
}

// Deletes given account. false is returned if given account does not belong to current wallet object.
func (w *Wallet)DeleteAccount(acc *Account) bool {
	if acc.wallet == w {
		acc.active = false
		return true
	}

	return false
}

// Returns account object for given public account key.
// If not matching account is found, nil is returned.
func (w *Wallet)FindAccountByPublicKey(pubkey string) *Account {

	for i, _ := range w.accounts {
		if w.accounts[i].active &&  w.accounts[i].publicKey == pubkey {
			return &w.accounts[i]
		}
	}

	return nil
}


// Returns first account matching given description string.
// Matching is performed case insensitive on sub string level..
// If not matching account is found, nil is returned.
func (w *Wallet)FindAccountByDescription(desc string) *Account {
	desc = strings.ToLower(desc)

	for i, _ := range w.accounts {
		if w.accounts[i].active {
			if strings.Contains(strings.ToLower(w.accounts[i].desc), desc) {
				return &w.accounts[i]
			}
		}
	}

	return nil
}

// Returns a slice containing all "own" accounts if current wallet, i.e.
// all but address book accounts.
func (w *Wallet)GetAccounts() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for i, _ := range w.accounts {
		if w.accounts[i].active && w.accounts[i].IsOwnAccount() {
			accounts = append(accounts, &w.accounts[i])
		}
	}

	return accounts
}

// Returns a slice containing all accounts with a private key,
//  i.e. generated and random accounts.
func (w *Wallet)GetSeedAccounts() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for i, _ := range w.accounts {
		if w.accounts[i].active && w.accounts[i].HasPrivateKey() {
			accounts = append(accounts, &w.accounts[i])
		}
	}

	return accounts
}

// Returns a slice containing all address book accounts.
func (w *Wallet)GetAddressBook() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for i, _ := range w.accounts {
		if w.accounts[i].active && w.accounts[i].IsAddressBookAccount() {
			accounts = append(accounts, &w.accounts[i])
		}
	}

	return accounts
}

// Returns a slice containing all assets of current wallet.
func (w *Wallet)GetAssets() []*Asset {
	assets := make([]*Asset, 0, len(w.assets))

	for _, a := range w.assets {
		if a.active {
			assets = append(assets, a)
		}
	}

	return assets
}

// Returns asset object for given issues and asset id.
// nil is return if no matching asset is found.
func (w *Wallet)FindAsset(issuer, assetId string) *Asset {
	for _, a := range w.assets {
		if a.active && a.issuer == issuer && a.assetId == assetId {
			return a
		}
	}

	return nil
}

// Returns a slice containing all assets that match the given issuer string.
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

// Creates a new asset and returns a Asset object for it.
// nil is returned if the given issues string is not a valid public account key or
// if the given assetId is not valid.
func (w *Wallet)AddAsset(issuer, assetId string) *Asset {
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

	a = w.newAsset()

	a.issuer = issuer
	a.assetId = assetId
	a.active = true

	return a
}	

// Deletes given asset from wallet.
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

// Returns trading pair for given assets. Return nil of no trading pair is defined for given assets.
func (w *Wallet)FindTradingPair(asset1, asset2 *Asset) *TradingPair {
	for _, tp := range w.tradingPairs {
		if tp.asset1 == asset1 && tp.asset2 == asset2 {
			return tp
		}
	}

	return nil
} 

// Adds a new trading pair to the wallet. If a trading pair for the given assets is already defined, the existing pair is returned.
// The native Lumen is represented bya nil asset. 
// For following error conditions nil is returned: assets do not belong to current wallet, assets as identical 
func (w *Wallet)AddTradingPair(asset1, asset2 *Asset) *TradingPair {
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

	return tp
}

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

func (w *Wallet)GetTradingPairs() []*TradingPair {
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
}

// Returns account type.
func (a *Account)Type() uint16 {
	return a.accountType
}

// Checks if current account is an own account, i.e. of type generated, random or watching.
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

// Checks if current account is an address book account..
func (a *Account)IsAddressBookAccount() bool {
	if a.accountType == AccountTypeAddressBook {
		return true
	}

	return false
}

// Checks true if current account holds a private key.
func (a *Account)HasPrivateKey() bool {
	switch a.accountType {
	case AccountTypeSEP0005:
		return true
	case AccountTypeRandom:
		return true
	}

	return false
}




// Returns description of account. Empty string is returned if no description is defined.
func (a *Account)GetDescription() string {
	return a.desc
}

// Sets description on account. If give description string is not valid a descriptive error is returned.
func (a *Account)SetDescription(desc string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	a.desc = desc

	return nil
}

// Returns memo text of account. Empty string is returned if no memo text is defined.
func (a *Account)GetMemoText() string {
	return a.memoText
}

// Sets memo text on account. If given memo text string is not valid a descriptive error is returned.
func (a *Account)SetMemoText(memo string) error {
	err := CheckMemoText(memo)
	if err != nil {
		return err
	}

	a.memoText = memo

	return nil
}

// Returns memo id of account. If no memo id is defined for current account, the boolean return value is false.
func (a *Account)GetMemoId() (bool, uint64) {
	if a.memoIdSet {
		return true, a.memoId
	}

	return false, 0
}

// Sets memo id on account.
func (a *Account)SetMemoId(memo uint64) {
	a.memoId = memo
	a.memoIdSet = true
}

// Clears memo id from account.
func (a *Account)ClearMemoId() {
	a.memoId = 0
	a.memoIdSet = false
}

// Returns public key of account.
func (a *Account)PublicKey() string {
	if !a.active {
		panic("account not active")
	}
	return a.publicKey
}

// Returns private key of account.
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

func (a *Asset)GetTradingPairs() []*TradingPair {
	tps := make([]*TradingPair, 0, a.tradingPairLink.Len())

	for itr := a.tradingPairLink.Front(); itr != nil; itr = itr.Next() {
		tps = append(tps, itr.Value.(*TradingPair))
	}
	
	return tps
}

// Returns description of asset. Empty string is returned if no description is defined.
func (a *Asset)GetDescription() string {
	return a.desc
}

// Sets description on asset. If give description string is not valid a descriptive error is returned, else nil.
func (a *Asset)SetDescription(desc string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	a.desc = desc

	return nil
}

func (a *Asset)Issuer() string {
	return a.issuer
}

func (a *Asset)AssetId() string {
	return a.assetId
}

func (tp *TradingPair)init(wallet *Wallet) {
	tp.wallet = wallet
	tp.desc = ""
	tp.asset1 = nil
	tp.asset2 = nil
}

// Returns description of trading pair. Empty string is returned if no description is defined.
func (tp *TradingPair)GetDescription() string {
	return tp.desc
}

// Sets description on tarding pair. If give description string is not valid a descriptive error is returned, else nil.
func (tp *TradingPair)SetDescription(desc string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	tp.desc = desc

	return nil
}

// Returns first asset of trading pair. nil denotes native Lumen.
func (tp *TradingPair)Asset1() *Asset {
	return tp.asset1
}

// Returns second asset of trading pair. nil denotes native Lumen.
func (tp *TradingPair)Asset2() *Asset {
	return tp.asset2
}


// Performs self test to ensure that hardware performs correct calculations.
// Failures are indicated by a non nil error. 
// All wallet creation methods run this self test as well and will panic if it fails.
// This function should be called by an application first in order to gracefully handle 
// hardware failures.
func SelfTest() error {
	if g_selfTestDone {
		return g_selfTestStatus
	}

	g_selfTestDone = true
	g_selfTestStatus = nil

	errPrefix := "stellarwallet self test: "

	mnwords := "cable spray genius state float twenty onion head street palace net private method loan turn phrase state blanket interest dry amazing dress blast tube"
	w := strings.Split(mnwords, " ")

	mnPw := "p4ssphr4se"
	wPw := "gBCdqqYVvCmJJAQOhtuwme8vvGArKDov"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		g_selfTestStatus = errors.New(errPrefix+"wallet creation from mnemonic seed failed")
		return g_selfTestStatus
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
		a := wallet.GenerateSep0005Account(&wPw)

		if a.PublicKey() != expectedKeys[2*i] {
			g_selfTestStatus = errors.New(errPrefix+"invalid public key generated")
			return g_selfTestStatus
		}
		if a.PrivateKey(&wPw)!= expectedKeys[2*i+1] {
			g_selfTestStatus = errors.New(errPrefix+"invalid seed generated")
			return g_selfTestStatus
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
			g_selfTestStatus = errors.New(errPrefix+"invalid public key generated")
			return g_selfTestStatus
		}
		if a.PrivateKey(&wPw)!= expectedKeys[2*i+1] {
			g_selfTestStatus = errors.New(errPrefix+"invalid seed returned")
			return g_selfTestStatus
		}
	}

	return nil
}
