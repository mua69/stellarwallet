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
}

type Asset struct {
	wallet *Wallet
	active bool

	desc string
	issuer string
	assetId string
}	

type Wallet struct {
	desc string

	masterSeed []byte

	bip39Seed []byte

	sep0005AccountCount uint16

	accounts []Account
	assets []Asset
}

func EraseByteBuffer(b []byte) {
	if b != nil {
		for i, _ := range b {
			b[i] = 0
		}
	}
}


func EraseString(s string) {
	EraseByteBuffer([]byte(s))
}

func CheckDescription(s string) error {
	if len(s) > 2000 {
		return errors.New("exceeds max length (2000 characters)")
	}

	return nil
}

func CheckPublicKey(s string) bool {
	_, err := strkey.Decode(strkey.VersionByteAccountID, s)

	if err != nil {
		return false
	}

	return true
}

func CheckPrivateKey(s *string) bool {
	_, err := strkey.Decode(strkey.VersionByteSeed, *s)

	if err != nil {
		return false
	}

	return true

}

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

func NewWallet(password *string) *Wallet {
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

func NewWalletFromMnemonic(walletPassword *string, mnemonic []string, mnemonicPassword *string) *Wallet {
	w := new(Wallet)

	key := deriveAesKey(walletPassword)
	defer EraseByteBuffer(key)

	seed, err := bip39.MnemonicToByteArray(strings.Join(mnemonic, " "))
	if err != nil {
		return nil
	}
	defer EraseByteBuffer(seed)
	
	seed = seed[:masterSeedLen]

	if len(seed) != masterSeedLen {
		fmt.Printf("seed len: %d", len(seed))
		panic("invalid master seed derived " )
	}

	w.encryptMasterSeed(seed, key)

	if !w.generateBip39Seed(key, mnemonic, mnemonicPassword) {
		return nil
	}

	return w
}

func ImportBinary(buf []byte) (w *Wallet, err error) {
	w = new(Wallet)

	err = w.readFromBufferCompressed(buf)

	if err != nil {
		return nil, err
	}

	return w, nil
}

func ImportBase64(data string) (w *Wallet, err error) {
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

func (w *Wallet)ExportBinary() []byte {
	return w.writeToBufferCompressed()
}

func (w *Wallet)ExportBase64() string {
	buf := w.writeToBufferCompressed()

	if buf == nil {
		return ""
	} else {
		return base64.StdEncoding.EncodeToString(buf)
	}
}

func (w *Wallet)clearAccounts() {
	for _, a := range w.accounts {
		a.active = false
		a.privateKey = nil
		a.publicKey = ""
		a.sep0005DerivationPath = ""
	}
}

func (w *Wallet)GetDescription() string {
	return w.desc
}

func (w *Wallet)SetDescription(desc string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	w.desc = desc

	return nil
}


func deriveAesKey(password *string) (key []byte) {
	return pbkdf2.Key([]byte(*password), []byte("stellarwallet"), 4096, 32, sha1.New)
}

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

func (w *Wallet)DeleteAccount(acc *Account) bool {
	if acc.wallet == w {
		acc.active = false
		return true
	}

	return false
}

func (w *Wallet)FindAccountByPublicKey(pubkey string) *Account {

	for i, _ := range w.accounts {
		if w.accounts[i].active &&  w.accounts[i].publicKey == pubkey {
			return &w.accounts[i]
		}
	}

	return nil
}

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

func (w *Wallet)GetAccounts() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for i, _ := range w.accounts {
		if w.accounts[i].active && w.accounts[i].IsOwnAccount() {
			accounts = append(accounts, &w.accounts[i])
		}
	}

	return accounts
}

func (w *Wallet)GetAddressBook() []*Account {
	accounts := make([]*Account, 0, len(w.accounts))

	for i, _ := range w.accounts {
		if w.accounts[i].active && w.accounts[i].IsAddressBookAccount() {
			accounts = append(accounts, &w.accounts[i])
		}
	}

	return accounts
}

func (w *Wallet)GetAssets() []*Asset {
	assets := make([]*Asset, 0, len(w.assets))

	for i, _ := range w.assets {
		a := &w.assets[i]
		if a.active {
			assets = append(assets, a)
		}
	}

	return assets
}

func (w *Wallet)FindAsset(issuer, assetId string) *Asset {
	for i,_ := range w.assets {
		a := &w.assets[i]

		if a.active && a.issuer == issuer && a.assetId == assetId {
			return a
		}
	}

	return nil
}

func (w *Wallet)FindAssetsByIssuer(issuer string) []*Asset {
	assets := make([]*Asset, 0, len(w.assets))

	for i,_ := range w.assets {
		a := &w.assets[i]

		if a.active && a.issuer == issuer {
			assets = append(assets, a)
		}
	}

	return assets
}

func (w *Wallet)newAsset() *Asset {
	for i, _ := range w.assets {
		a := &w.assets[i]
		if !a.active {
			a.init(w)
			return a
		}
	}

	w.assets = append(w.assets, Asset{})

	a := &w.assets[len(w.assets)-1]

	a.init(w)

	return a
}

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
	
func (w *Wallet)DeleteAsset(ass *Asset) bool {
	if ass.wallet == w {
		ass.active = false
		return true
	}

	return false
}

func (a *Account)init(wallet *Wallet) {
	a.wallet = wallet
	a.accountType = AccountTypeUndefined
	a.desc = ""
	a.publicKey = ""
	a.privateKey = nil
	a.sep0005DerivationPath = ""
}

func (a *Account)Type() uint16 {
	return a.accountType
}

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

func (a *Account)IsAddressBookAccount() bool {
	if a.accountType == AccountTypeAddressBook {
		return true
	}

	return false
}

func (a *Account)HasPrivateKey() bool {
	switch a.accountType {
	case AccountTypeSEP0005:
		return true
	case AccountTypeRandom:
		return true
	}

	return false
}



func (a *Account)GetDescription() string {
	return a.desc
}

func (a *Account)SetDescription(desc string) error {
	err := CheckDescription(desc)
	if err != nil {
		return err
	}

	a.desc = desc

	return nil
}



func (a *Account)PublicKey() string {
	if !a.active {
		panic("account not active")
	}
	return a.publicKey
}

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
	a.issuer = ""
	a.assetId = ""
}

func (a *Asset)GetDescription() string {
	return a.desc
}

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
