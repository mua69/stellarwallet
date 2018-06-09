package stellarwallet

import(
	"strings"
	"bytes"
	"testing"
	"encoding/hex"
	"fmt"
	"github.com/bartekn/go-bip39"
)


func TestAes1(t *testing.T) {
	pw := "stellarwalletpw"
	key := deriveAesKey(&pw)

	aesTestData1 := []byte{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 }

	l := len(aesTestData1)

	t.Logf("in : %s\n", hex.EncodeToString(aesTestData1))

	enc := aesEncrypt(aesTestData1, key)

	t.Logf("enc: %s\n", hex.EncodeToString(enc))

	aesDecrypt(enc, key)

	t.Logf("dec: %s\n", hex.EncodeToString(enc))


	if bytes.Compare(aesTestData1, enc[0:l]) != 0 {
		t.Fail()
	}

}

func TestAes2(t *testing.T) {
	pw := "stellarwalletpw"
	pw1 := "stellarwalletpe"
	key1 := deriveAesKey(&pw)
	key2 := deriveAesKey(&pw1)

	aesTestData1 := []byte{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 }

	l := len(aesTestData1)

	t.Logf("in : %s\n", hex.EncodeToString(aesTestData1))

	enc := aesEncrypt(aesTestData1, key1)

	t.Logf("enc: %s\n", hex.EncodeToString(enc))

	aesDecrypt(enc, key2)

	t.Logf("dec: %s\n", hex.EncodeToString(enc))


	if bytes.Compare(aesTestData1, enc[0:l]) == 0 {
		t.Fail()
	}

}

func TestAes3(t *testing.T) {
	pw := "stellarwalletpw"
	key := deriveAesKey(&pw)

	aesTestData1 := []byte{ 1, }
	l := len(aesTestData1)

	t.Logf("in : %s\n", hex.EncodeToString(aesTestData1))

	enc := aesEncrypt(aesTestData1, key)

	t.Logf("enc: %s\n", hex.EncodeToString(enc))

	aesDecrypt(enc, key)

	t.Logf("dec: %s\n", hex.EncodeToString(enc))


	if bytes.Compare(aesTestData1, enc[0:l]) != 0 {
		t.Fail()
	}

}

func TestAes4(t *testing.T) {
	pw := "stellarwalletpw"
	key := deriveAesKey(&pw)

	aesTestData1 := []byte{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }

	l := len(aesTestData1)

	t.Logf("in : %s\n", hex.EncodeToString(aesTestData1))

	enc := aesEncrypt(aesTestData1, key)

	t.Logf("enc: %s\n", hex.EncodeToString(enc))

	aesDecrypt(enc, key)

	t.Logf("dec: %s\n", hex.EncodeToString(enc))


	if bytes.Compare(aesTestData1, enc[0:l]) != 0 {
		t.Fail()
	}

}

func TestAes5(t *testing.T) {
	pw := "stellarwalletpw"
	key := deriveAesKey(&pw)

	aesTestData1 := []byte{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }

	l := len(aesTestData1)

	t.Logf("in : %s\n", hex.EncodeToString(aesTestData1))

	enc := aesEncrypt(aesTestData1, key)

	t.Logf("enc: %s\n", hex.EncodeToString(enc))

	aesDecrypt(enc, key)

	t.Logf("dec: %s\n", hex.EncodeToString(enc))


	if bytes.Compare(aesTestData1, enc[0:l]) != 0 {
		t.Fail()
	}

}

func TestWallet1(t *testing.T) {
	pw1 := "pwTest1!%$ 123 PW"
	pw2 := "pwTest2!%$ 123 PW"
	w := NewWallet(&pw1)

	if w == nil {
		t.Fatalf("new wallet failed")
	}

	if !w.CheckPassword(&pw1) {
		t.Fatalf("pw1 check failed")
	}

	if w.CheckPassword(&pw2) {
		t.Fatalf("pw1 check failed")
	}
}

func TestWallet2(t *testing.T) {
	pw1 := ""
	pw2 := "pwTest2!%$ 123 PW"
	w := NewWallet(&pw1)

	if w == nil {
		t.Fatalf("new wallet failed")
	}

	if !w.CheckPassword(&pw1) {
		t.Fatalf("pw1 check failed")
	}

	if w.CheckPassword(&pw2) {
		t.Fatalf("pw1 check failed")
	}
}


func TestMnemonic1(t *testing.T) {
	pw := "pwTest1!%$ 123 PW"
	w := NewWallet(&pw)

	words := w.Bip39Mnemonic(&pw)

	if words == nil {
		t.Logf("new mnemonic failed")
		t.FailNow()
	}

	t.Logf("Mnemonic: %s", strings.Join(words, " "))

	if len(words) != 24 {
		t.Logf("unexpected mnemonic length: %d", len(words))
		t.Fail()
	}
}

func TestChangePassword1(t *testing.T) {
	pw1 := "pass1234"
	pw2 := "12pass34"


	w := NewWallet(&pw1)

	if w == nil {
		t.Fatalf("new wallet failed")
	}

	if !w.CheckPassword(&pw1) {
		t.Fatalf("pw1 check failed")
	}

	if !w.ChangePassword(&pw1, &pw2) {
		t.Fatalf("change password failed")
	}

	if !w.CheckPassword(&pw2) {
		t.Fatalf("pw2 check failed")
	}
}

func TestChangePassword2(t *testing.T) {
	pw1 := "pass1234"
	pw2 := "12pass34"

	w1 := createWallet1(t, pw1)

	if !w1.CheckPassword(&pw1) {
		t.Fatalf("pw1 check failed")
	}

	data := w1.ExportBinary()
	
	if data == nil {
		t.Fatalf("export failed")
	}

	w2, err := ImportBinary(data)

	if err != nil {
		t.Fatalf("import failed: %s", err.Error() )
	}

	if !w2.ChangePassword(&pw1, &pw2) {
		t.Fatalf("change password failed")
	}

	if !w2.CheckPassword(&pw2) {
		t.Fatalf("pw2 check failed")
	}

	compareWallets(t, true, pw1, pw2, w1, w2)

	if w2.GenerateAccount(&pw2) == nil {
		t.Fatalf("GenerateAccount failed")
	}

}

func TestGenBip39Seed1(t *testing.T) {
	words := "merge silver adult unusual dilemma air winner safe smile region oil maximum gorilla process link aspect spoon junk crowd employ fury case join one"
	w := strings.Split(words, " ")

	t.Logf("Mnemonic: %s", words)

	if len(w) != 24 {
		t.Logf("unexpected mnemonic length: %d", len(w))
		t.Fail()
	}

	mnPw := ""
	wPw := "stellarwalletpw"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}

	t.Logf("bip39seed enc: %s", hex.EncodeToString(wallet.bip39Seed[:bip39SeedLen]))

	expectedSeedEnc := "d9e46ef7afca3c7645f489d7c5a5dba3ad4e9ffe63aa180613b78073db0438d87b9772ffd307db95cc6ed4feea9197d5ebad821b4a38c5a966d4ac3fc2e08021"

	if hex.EncodeToString(wallet.bip39Seed[:bip39SeedLen]) != expectedSeedEnc {
		t.Logf("seed does not match")
		t.FailNow()
	}

	seed, _ := bip39.NewSeedWithErrorChecking(strings.Join(w, " "), mnPw)

	dec := wallet.decryptBip39Seed(deriveAesKey(&wPw))

	if dec == nil {
		t.Logf("seed decryption failed")
		t.FailNow()
	}

	if bytes.Compare(seed, dec) != 0 {
		t.Logf("decrypted seed does not match")
		t.FailNow()
	}

	wordsFromSeed := wallet.Bip39Mnemonic(&wPw)

	if wordsFromSeed == nil {
		t.Logf("retrieving mnemonic word list from seed failed")
		t.FailNow()
	}

	t.Logf("Words from seed: %s", strings.Join(wordsFromSeed, " ") )

	if strings.Join(wordsFromSeed, " ") != words {
		t.Logf("word lists do not match")
	}
}

func TestGenBip39Seed2(t *testing.T) {
	words := "merge silver adult unusual dilemma air winner safe smile region oil maximum gorilla process link aspect spoon junk crowd employ fury case join one"
	w := strings.Split(words, " ")

	t.Logf("Mnemonic: %s", words)

	if len(w) != 24 {
		t.Logf("unexpected mnemonic length: %d", len(w))
		t.Fail()
	}

	mnPw := "mnemonicpasswordtest"
	wPw := "stellarwalletpw"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}

	t.Logf("bip39seed enc: %s", hex.EncodeToString(wallet.bip39Seed[:bip39SeedLen]))

	expectedSeedEnc := "e6c9a30cc4ed843dbcbb7e5643d1481f07bb06ccfa250bc5192ceb05796945f944898ae88a5ad11fe49614ea41abe9bc03bf82b28d2946965b9bde1b9878acc1"

	if hex.EncodeToString(wallet.bip39Seed[:bip39SeedLen]) != expectedSeedEnc {
		t.Logf("seed does not match")
		t.FailNow()
	}

	seed, _ := bip39.NewSeedWithErrorChecking(strings.Join(w, " "), mnPw)

	wPw1 := "stellarwalletpw"
	dec := wallet.decryptBip39Seed(deriveAesKey(&wPw1))

	if dec == nil {
		t.Logf("seed decryption failed")
		t.FailNow()
	}

	if bytes.Compare(seed, dec) != 0 {
		t.Logf("decrypted seed does not match")
		t.FailNow()
	}

	wordsFromSeed := wallet.Bip39Mnemonic(&wPw)

	if wordsFromSeed == nil {
		t.Logf("retrieving mnemonic word list from seed failed")
		t.FailNow()
	}

	t.Logf("Words from seed: %s", strings.Join(wordsFromSeed, " ") )

	if strings.Join(wordsFromSeed, " ") != words {
		t.Logf("word lists do not match")
	}
}


func TestGenSep0005Account1(t *testing.T) {
	words := "merge silver adult unusual dilemma air winner safe smile region oil maximum gorilla process link aspect spoon junk crowd employ fury case join one"
	w := strings.Split(words, " ")

	t.Logf("Mnemonic: %s", words)

	if len(w) != 24 {
		t.Logf("unexpected mnemonic length: %d", len(w))
		t.Fail()
	}
	
	mnPw := "mnemonicpasswordtest"
	wPw := "stellarwalletpw"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}

	expectedKeys := []string{
		"GAOOWGZIMGN3HGKMAX4WLCEDUEBWLZWCJVCXEJN7BB4BREJ6N3PFA5HZ", "SAFI4KRSMSW7OF5UCN47NCWINORPNHHJZJEAKF7DBI7IIACUKZFVT3UR",
		"GBIKJJORC7APJRDRVX2RCBDMUCCK73U6JXSQL4T7AHT7GRTY73KTS5MZ", "SDA4QBYTQFXP2CWUSBBEX22RWQAYIJEBQSAO6QNO4LASTFE2JCVUVROJ",
		"GBCKQ4CHJF3OPKSJQD6G7NBSGMMQ5HDD77ZIKDIREBFBFCRMHJIOELLM", "SCPISHJZ6E5TN6J2OFLIKJ26UTQRDNTT2VJHDJIKD4LWQMKUTAQAG6UV"}


	for i := 0; i < len(expectedKeys)/2; i++ {
		a := wallet.GenerateAccount(&wPw)

		if !a.active {
			t.Error("account not active")
		} 
		if a.accountType != AccountTypeSEP0005 {
			t.Error("account type mismatch")
		}
		if a.PublicKey() != expectedKeys[2*i] {
			t.Error("public key mismatch")
		}
		if a.PrivateKey(&wPw)!= expectedKeys[2*i+1] {
			t.Error("private key mismatch")
		}

		t.Logf("account type: %d", a.accountType)
		t.Logf("derivation path: %s", a.sep0005DerivationPath)
		t.Logf("public key : %s", a.publicKey)
		t.Logf("private key: %s", a.PrivateKey(&wPw))
	}

	wordsFromSeed := wallet.Bip39Mnemonic(&wPw)

	if wordsFromSeed == nil {
		t.Logf("retrieving mnemonic word list from seed failed")
		t.FailNow()
	}

	t.Logf("Words from seed: %s", strings.Join(wordsFromSeed, " ") )

	if strings.Join(wordsFromSeed, " ") != words {
		t.Logf("word lists do not match")
	}

}

func TestGenSep0005Account2(t *testing.T) {
	words := "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better"
	w := strings.Split(words, " ")

	t.Logf("Mnemonic: %s", words)

	if len(w) != 24 {
		t.Logf("unexpected mnemonic length: %d", len(w))
		t.Fail()
	}
	
	mnPw := ""
	wPw := "stellarwalletpw"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}

	expectedKeys := []string{
		"GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", "SAEWIVK3VLNEJ3WEJRZXQGDAS5NVG2BYSYDFRSH4GKVTS5RXNVED5AX7",
		"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", "SBKSABCPDWXDFSZISAVJ5XKVIEWV4M5O3KBRRLSPY3COQI7ZP423FYB4",
		"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", "SD5CCQAFRIPB3BWBHQYQ5SC66IB2AVMFNWWPBYGSUXVRZNCIRJ7IHESQ",
		"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", "SBSGSAIKEF7JYQWQSGXKB4SRHNSKDXTEI33WZDRR6UHYQCQ5I6ZGZQPK",
		"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", "SBIZH53PIRFTPI73JG7QYA3YAINOAT2XMNAUARB3QOWWVZVBAROHGXWM",
		"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", "SCVM6ZNVRUOP4NMCMMKLTVBEMAF2THIOMHPYSSMPCD2ZU7VDPARQQ6OY",
		"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "SBSHUZQNC45IAIRSAHMWJEJ35RY7YNW6SMOEBZHTMMG64NKV7Y52ZEO2",
		"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", "SC2QO2K2B4EBNBJMBZIKOYSHEX4EZAZNIF4UNLH63AQYV6BE7SMYWC6E",
		"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", "SCGMC5AHAAVB3D4JXQPCORWW37T44XJZUNPEMLRW6DCOEARY3H5MAQST",
		"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", "SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF"}

	for i := 0; i < 10; i++ {
		a := wallet.GenerateAccount(&wPw)

		if !a.active {
			t.Error("account not active")
		} 
		if a.accountType != AccountTypeSEP0005 {
			t.Error("account type mismatch")
		}
		if a.PublicKey() != expectedKeys[2*i] {
			t.Error("public key mismatch")
		}
		if a.PrivateKey(&wPw)!= expectedKeys[2*i+1] {
			t.Error("private key mismatch")
		}

		t.Logf("account type: %d", a.accountType)
		t.Logf("derivation path: %s", a.sep0005DerivationPath)
		t.Logf("public key : %s", a.publicKey)
		t.Logf("private key: %s", a.PrivateKey(&wPw))
	}

	wordsFromSeed := wallet.Bip39Mnemonic(&wPw)

	if wordsFromSeed == nil {
		t.Logf("retrieving mnemonic word list from seed failed")
		t.FailNow()
	}

	t.Logf("Words from seed: %s", strings.Join(wordsFromSeed, " ") )

	if strings.Join(wordsFromSeed, " ") != words {
		t.Logf("word lists do not match")
	}

}

//https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
func TestGenSep0005Account3(t *testing.T) {
	words := "cable spray genius state float twenty onion head street palace net private method loan turn phrase state blanket interest dry amazing dress blast tube"
	w := strings.Split(words, " ")

	t.Logf("Mnemonic: %s", words)

	if len(w) != 24 {
		t.Logf("unexpected mnemonic length: %d", len(w))
		t.Fail()
	}
	
	mnPw := "p4ssphr4se"
	wPw := "stellarwalletpw"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}

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

		if !a.active {
			t.Error("account not active")
		} 
		if a.accountType != AccountTypeSEP0005 {
			t.Error("account type mismatch")
		}
		if a.PublicKey() != expectedKeys[2*i] {
			t.Error("public key mismatch")
		}
		if a.PrivateKey(&wPw)!= expectedKeys[2*i+1] {
			t.Error("private key mismatch")
		}

		t.Logf("account type: %d", a.accountType)
		t.Logf("derivation path: %s", a.sep0005DerivationPath)
		t.Logf("public key : %s", a.publicKey)
		t.Logf("private key: %s", a.PrivateKey(&wPw))
	}

	wordsFromSeed := wallet.Bip39Mnemonic(&wPw)

	if wordsFromSeed == nil {
		t.Logf("retrieving mnemonic word list from seed failed")
		t.FailNow()
	}

	t.Logf("Words from seed: %s", strings.Join(wordsFromSeed, " ") )

	if strings.Join(wordsFromSeed, " ") != words {
		t.Logf("word lists do not match")
	}

	accounts := wallet.SeedAccounts()

	if len(accounts) != 10 {
		t.Fatalf("unexpect account count: %d", len(accounts))
	}

}

func TestRecoverAccounts1(t *testing.T) {
	wPw := "stellarwalletpw"

	w := createWalletStd1(t, wPw)

	fundedCheckResults := []struct{ adr string
		res bool } {
			{ "GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", false},
			{"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", false},
			{"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", false},
			{"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", false},
			{"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", false},
			{"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", false},
			{"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", false},
			{"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", false},
			{"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", false},
			{"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", false},
			{"SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF", false}}
	
	fundedCheck := func (adr string) bool {
		for _, r := range fundedCheckResults {
			if r.adr == adr {
				return r.res
			}
		}
		return false
	}

	w.RecoverAccounts(&wPw, 1, fundedCheck)

	if len(w.Accounts()) != 0 {
		t.Fatal("invalid account count")
	}

	a := w.GenerateAccount(&wPw)

	if a.PublicKey() != "GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ" {
		t.Fatal("expected account not generated after recovery")
	}


}

func TestRecoverAccounts2(t *testing.T) {
	wPw := "stellarwalletpw"

	w := createWalletStd1(t, wPw)



	fundedCheckResults := []struct{ adr string
		res bool
		exp bool} {
			{"GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", true, true},
			{"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", false, false},
			{"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", false, false},
			{"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", false, false},
			{"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", false, false},
			{"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", false, false},
			{"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", false, false},
			{"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", false, false},
			{"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", false, false},
			{"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", false, false},
			{"SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF", false, false}}
	
	fundedCheck := func (adr string) bool {
		for _, r := range fundedCheckResults {
			if r.adr == adr {
				return r.res
			}
		}
		return false
	}

	w.RecoverAccounts(&wPw, 1, fundedCheck)
	
	if len(w.Accounts()) != 1 {
		t.Fatal("invalid account count")
	}

	for _, r := range fundedCheckResults {
		if r.exp {
			if w.FindAccountByPublicKey(r.adr) == nil {
				t.Fatal("expected account not found")
			}
		}
	}

	a := w.GenerateAccount(&wPw)

	if a.PublicKey() != "GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO" {
		t.Fatal("expected account not generated after recovery")
	}

}

func TestRecoverAccounts3(t *testing.T) {
	wPw := "stellarwalletpw"

	w := createWalletStd1(t, wPw)

	fundedCheckResults := []struct{ adr string
		res bool
		exp bool} {
			{"GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", false, false},
			{"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", true, true},
			{"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", false, false},
			{"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", true, true},
			{"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", false, false},
			{"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", false, false},
			{"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", true, false},
			{"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", false, false},
			{"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", false, false},
			{"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", false, false},
			{"SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF", false, false}}
	
	fundedCheck := func (adr string) bool {
		for _, r := range fundedCheckResults {
			if r.adr == adr {
				return r.res
			}
		}
		return false
	}

	w.RecoverAccounts(&wPw, 1, fundedCheck)
	
	if len(w.Accounts()) != 2 {
		t.Fatal("invalid account count")
	}

	for _, r := range fundedCheckResults {
		if r.exp {
			if w.FindAccountByPublicKey(r.adr) == nil {
				t.Fatal("expected account not found")
			}
		}
	}

	a := w.GenerateAccount(&wPw)

	if a.PublicKey() != "GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN" {
		t.Fatal("expected account not generated after recovery")
	}

}

func TestRecoverAccounts4(t *testing.T) {
	wPw := "stellarwalletpw"

	w := createWalletStd1(t, wPw)

	fundedCheckResults := []struct{ adr string
		res bool
		exp bool} {
			{"GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", false, false},
			{"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", true, true},
			{"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", false, false},
			{"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", true, true},
			{"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", false, false},
			{"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", false, false},
			{"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", true, true},
			{"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", false, false},
			{"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", false, false},
			{"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", false, false},
			{"SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF", true, false}}
	
	fundedCheck := func (adr string) bool {
		for _, r := range fundedCheckResults {
			if r.adr == adr {
				return r.res
			}
		}
		return false
	}

	w.RecoverAccounts(&wPw, 2, fundedCheck)
	
	if len(w.Accounts()) != 3 {
		t.Fatal("invalid account count")
	}

	for _, r := range fundedCheckResults {
		if r.exp {
			if w.FindAccountByPublicKey(r.adr) == nil {
				t.Fatal("expected account not found")
			}
		}
	}

	a := w.GenerateAccount(&wPw)

	if a.PublicKey() != "GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4" {
		t.Fatal("expected account not generated after recovery")
	}

}

func TestRecoverAccounts5(t *testing.T) {
	wPw := "stellarwalletpw"

	w := createWalletStd1(t, wPw)



	fundedCheckResults := []struct{ adr string
		res bool
		exp bool} {
			{"GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", true, true},
			{"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", false, false},
			{"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", true, false},
			{"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", false, false},
			{"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", false, false},
			{"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", false, false},
			{"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", false, false},
			{"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", false, false},
			{"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", false, false},
			{"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", false, false},
			{"SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF", false, false}}
	
	fundedCheck := func (adr string) bool {
		for _, r := range fundedCheckResults {
			if r.adr == adr {
				return r.res
			}
		}
		return false
	}

	w.RecoverAccounts(&wPw, 0, fundedCheck)
	
	if len(w.Accounts()) != 1 {
		t.Fatal("invalid account count")
	}

	for _, r := range fundedCheckResults {
		if r.exp {
			if w.FindAccountByPublicKey(r.adr) == nil {
				t.Fatal("expected account not found")
			}
		}
	}

	a := w.GenerateAccount(&wPw)

	if a.PublicKey() != "GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO" {
		t.Fatal("expected account not generated after recovery")
	}

}

func TestRecoverAccounts6(t *testing.T) {
	wPw := "stellarwalletpw"

	w := createWalletStd1(t, wPw)

	fundedCheckResults := []struct{ adr string
		res bool
		exp bool} {
			{"GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ", true, true},
			{"GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", true, true},
			{"GDYF7GIHS2TRGJ5WW4MZ4ELIUIBINRNYPPAWVQBPLAZXC2JRDI4DGAKU", true, true},
			{"GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD", false, false},
			{"GAXG3LWEXWCAWUABRO6SMAEUKJXLB5BBX6J2KMHFRIWKAMDJKCFGS3NN", false, false},
			{"GA6RUD4DZ2NEMAQY4VZJ4C6K6VSEYEJITNSLUQKLCFHJ2JOGC5UCGCFQ", false, false},
			{"GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", false, false},
			{"GBJ646Q524WGBN5X5NOAPIF5VQCR2WZCN6QZIDOSY6VA2PMHJ2X636G4", false, false},
			{"GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", false, false},
			{"GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7", false, false},
			{"SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF", false, false}}
	
	fundedCheck := func (adr string) bool {
		for _, r := range fundedCheckResults {
			if r.adr == adr {
				return r.res
			}
		}
		return false
	}

	w.RecoverAccounts(&wPw, 0, fundedCheck)
	
	if len(w.Accounts()) != 3 {
		t.Fatal("invalid account count")
	}

	for _, r := range fundedCheckResults {
		if r.exp {
			if w.FindAccountByPublicKey(r.adr) == nil {
				t.Fatal("expected account not found")
			}
		}
	}

	a := w.GenerateAccount(&wPw)

	if a.PublicKey() != "GAFLH7DGM3VXFVUID7JUKSGOYG52ZRAQPZHQASVCEQERYC5I4PPJUWBD" {
		t.Fatal("expected account not generated after recovery")
	}

}

func TestRecoverAccounts7(t *testing.T) {
	wPw := "stellarwalletpw"

	w := createWalletStd1(t, wPw)

	a := w.GenerateAccount(&wPw)
	
	fundedCheck := func (adr string) bool {
		return false
	}

	w.RecoverAccounts(&wPw, 0, fundedCheck)
	
	if len(w.Accounts()) != 1 {
		t.Fatal("invalid account count")
	}

	a = w.GenerateAccount(&wPw)

	if a.PublicKey() != "GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO" {
		t.Fatal("expected account not generated after recovery")
	}

}


func TestAddRandomAccount1(t *testing.T) {
	pw := "gBCdqqYVvCmJJAQOhtuwme8vvGArKDov"

	w := NewWallet(&pw)

	seed := "invalid"

	a := w.AddRandomAccount(&seed, &pw)

	if a != nil {
		t.Fatalf("invalid seed not rejected")
	}

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
		"GBOSMFQYKWFDHJWCMCZSMGUMWCZOM4KFMXXS64INDHVCJ2A2JAABCYRR", "SDXDYPDNRMGOF25AWYYKPHFAD3M54IT7LCLG7RWTGR3TS32A4HTUXNOS",
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
		a = w.AddRandomAccount(&expectedKeys[2*i+1], &pw)

		if a == nil {
			t.Fatalf("add account failed")
		}
		
		if !a.active {
			t.Error("account not active")
		} 
		if a.accountType != AccountTypeRandom {
			t.Error("account type mismatch")
		}
		if a.PublicKey() != expectedKeys[2*i] {
			t.Error("public key mismatch")
		}
		if a.PrivateKey(&pw)!= expectedKeys[2*i+1] {
			t.Error("private key mismatch")
		}

		t.Logf("account type: %d", a.accountType)
		t.Logf("public key : %s", a.publicKey)
		t.Logf("private key: %s", a.PrivateKey(&pw))
	}

	accounts := w.SeedAccounts()

	if len(accounts) != 23 {
		t.Fatalf("unexpect account count: %d", len(accounts))
	}
}

func TestAddWatchingAccount1(t *testing.T) {
	pw := "gBCdqqYVvCmJJAQOhtuwme8vvGArKDov"

	w := NewWallet(&pw)


	k1 := "invalid"
	k2 := "SAFWTGXVS7ELMNCXELFWCFZOPMHUZ5LXNBGUVRCY3FHLFPXK4QPXYP2X"
	k3 := "GBCKQ4CHJF3OPKSJQD6G7NBSGMMQ5HDD77ZIKDIREBFBFCRMHJIOELLN" // wrong checksum
	k4 := "GBCKQ4CHJF3OPKSJQD6G7NBSGMMQ5HDD77ZIKDIREBFBFCRMHJIOELLM" 

	a := w.AddWatchingAccount(k1)

	if a != nil {
		t.Fatalf("invalid pubkey accepted")
	}

	a = w.AddWatchingAccount(k2)

	if a != nil {
		t.Fatalf("invalid pubkey accepted")
	}
	
	a = w.AddWatchingAccount(k3)

	if a != nil {
		t.Fatalf("invalid pubkey accepted")
	}

	a = w.AddWatchingAccount(k4)

	if a == nil {
		t.Fatalf("add account failed")
	}
	
	
	if a.accountType != AccountTypeWatching {
		t.Fatalf("account type mismatch")
	}
	if a.PublicKey() != k4 {
		t.Fatalf("public key mismatch")
	}

	a.SetDescription("Test Description")

	a = w.AddWatchingAccount(k4)

	if a != nil {
		t.Fatalf("add account twice succeeded")
	}

	accounts := w.Accounts()
	
	if len(accounts) != 1 {
		t.Fatalf("unexpected account count")
	}

	a = w.FindAccountByPublicKey(k3)
	if a != nil {
		t.Fatalf("unexpected account found")
	}

	a = w.FindAccountByPublicKey(k4)
	if a == nil {
		t.Fatalf("account not found")
	}

	a = w.FindAccountByDescription("test")

	if a == nil {
		t.Fatalf("account not found")
	}

	a = w.FindAccountByDescription("no match")

	if a != nil {
		t.Fatalf("unexpected account found")
	}
	
	accounts = w.SeedAccounts()

	if len(accounts) != 0 {
		t.Fatalf("unexpect account count: %d", len(accounts))
	}

}

func TestAddAddressBookAccount1(t *testing.T) {
	pw := "gBCdqqYVvCmJJAQOhtuwme8vvGArKDov"

	w := NewWallet(&pw)


	k1 := "invalid"
	k2 := "SAFWTGXVS7ELMNCXELFWCFZOPMHUZ5LXNBGUVRCY3FHLFPXK4QPXYP2X"
	k3 := "GBCKQ4CHJF3OPKSJQD6G7NBSGMMQ5HDD77ZIKDIREBFBFCRMHJIOELLN" // wrong checksum
	k4 := "GBCKQ4CHJF3OPKSJQD6G7NBSGMMQ5HDD77ZIKDIREBFBFCRMHJIOELLM" 

	a := w.AddAddressBookAccount(k1)

	if a != nil {
		t.Fatalf("invalid pubkey accepted")
	}
	
	a = w.AddAddressBookAccount(k2)

	if a != nil {
		t.Fatalf("invalid pubkey accepted")
	}
	
	a = w.AddAddressBookAccount(k3)

	if a != nil {
		t.Fatalf("invalid pubkey accepted")
	}

	a = w.AddAddressBookAccount(k4)

	if a == nil {
		t.Fatalf("add account failed")
	}

	if a.SetMemoText("too long       ds            sadasd           ds") == nil {
		t.Fatalf("SetMemoText accepted invald string")
	}

	if a.SetMemoText("memo text") != nil {
		t.Fatalf("SetMemoText failed")
	}

	if a.MemoText() != "memo text" {
		t.Fatalf("MemoText failed")
	}
	
	
	
	if a.accountType != AccountTypeAddressBook {
		t.Fatalf("account type mismatch")
	}
	if a.PublicKey() != k4 {
		t.Fatalf("public key mismatch")
	}

	a = w.AddAddressBookAccount(k4)

	if a != nil {
		t.Fatalf("add account twice succeeded")
	}

	accounts := w.AddressBook()
	
	if len(accounts) != 1 {
		t.Fatalf("unexpected account count")
	}

	a = w.FindAccountByPublicKey(k3)
	if a != nil {
		t.Fatalf("unexpected account found")
	}

	a = w.FindAccountByPublicKey(k4)
	if a == nil {
		t.Fatalf("account not found")
	}

	if !w.DeleteAccount(a) {
		t.Fatalf("remove account faild")
	}

	accounts = w.AddressBook()
	
	if len(accounts) != 0 {
		t.Fatalf("unexpected account count")
	}
}

func TestAsset1(t *testing.T) {
	w := createWallet2(t, "pass")

	a := w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "EURT")
	if a == nil {
		t.Fatal("add asset failed")
	}

	err := a.SetDescription("asset description") 
	if err != nil {
		t.Fatalf("set description failed: %s", err.Error())
	}

	a = w.AddAsset("invalid", "EURT10eu")
	if a != nil {
		t.Fatal("invalid issuer accepted")
	}

	a = w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "")
	if a != nil {
		t.Fatal("invalid assetId accepted")
	}

	a = w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "E U")
	if a != nil {
		t.Fatal("invalid assetId accepted")
	}

	a = w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "1234567890123")
	if a != nil {
		t.Fatal("invalid assetId accepted")
	}

	a = w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "EURT1")
	if a == nil {
		t.Fatal("add asset failed")
	}

	a = w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "EURT2")
	if a == nil {
		t.Fatal("add asset failed")
	}

	if !w.DeleteAsset(a) {
		t.Fatal("delete asset failed")
	}

	assets := w.Assets()
	if len(assets) != 2 {
		t.Fatal("unexpected asset count")
	}

	assets = w.FindAssetsByIssuer("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS")
	if len(assets) != 2 {
		t.Fatal("unexpected find asset count")
	}
	
	a = w.FindAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "EURT")

	if a == nil {
		t.Fatal("asset not found")
	}

	if a.Description() != "asset description" {
		t.Fatal("description mismatch")
	}
	
	a = w.FindAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "EURT2")

	if a != nil {
		t.Fatal("unexpected asset found")
	}
}

func TestTradingPair1(t *testing.T) {
	w := createWallet3(t, "wallet password")

	a1 := w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "EURT")
	a2 := w.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "USDT")
	a3 := w.AddAsset("GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO", "USDT")

	if a1 == nil || a2 == nil || a3 == nil {
		t.Fatalf("add asset failed")
	}

	tp := w.AddTradingPair(nil, nil)
	if tp != nil {
		t.Fatalf("add asset: invalid args accepted")
	}

	tp = w.AddTradingPair(a1, a1)
	if tp != nil {
		t.Fatalf("add asset: invalid args accepted")
	}

	tp1 := w.AddTradingPair(a1, a2)
	tp2 := w.AddTradingPair(a1, a3)
	tp3 := w.AddTradingPair(a1, nil)
	tp4 := w.AddTradingPair(nil, a1)
	tp5 := w.AddTradingPair(nil, a2)

	if tp1 == nil || tp2 == nil || tp3 == nil || tp4 == nil || tp5 == nil {
		t.Fatalf("add trading pair failed")
	}

	if tp1.SetDescription("test description") != nil {
		t.Fatalf("set descripton failed")
	}

	if w.DeleteAsset(a1) {
		t.Fatalf("delete asset: succeeded though used in trading pair")
	}

	if w.DeleteAsset(a2) {
		t.Fatalf("delete asset: succeeded though used in trading pair")
	}

	if w.DeleteAsset(a3) {
		t.Fatalf("delete asset: succeeded though used in trading pair")
	}

	if len(a1.TradingPairs()) != 4 {
		t.Fatalf("invalid trading pairs count for a1")
	}

	if len(a2.TradingPairs()) != 2 {
		t.Fatalf("invalid trading pairs count for a2")
	}

	if len(a3.TradingPairs()) != 1 {
		t.Fatalf("invalid trading pairs count for a3")
	}
	
	tps := w.TradingPairs()

	if len(tps) != 5 {
		t.Fatalf("invalid trading pairs count")
	}

	if !w.DeleteTradingPair(tp1) {
		t.Fatalf("delete trading pair failed")
	}

	if !w.DeleteTradingPair(tp5) {
		t.Fatalf("delete trading pair failed")
	}

	if !w.DeleteAsset(a2) {
		t.Fatalf("delete asset failed")
	}
	

	tps = w.TradingPairs()

	if len(tps) != 3 {
		t.Fatalf("invalid trading pairs count")
	}
	
	if len(a1.TradingPairs()) != 3 {
		t.Fatalf("invalid trading pairs count for a1")
	}

	if len(a2.TradingPairs()) != 0 {
		t.Fatalf("invalid trading pairs count for a2")
	}

	if len(a3.TradingPairs()) != 1 {
		t.Fatalf("invalid trading pairs count for a3")
	}

	
}

func createWallet1(t *testing.T, wPw string) *Wallet {
	words := "merge silver adult unusual dilemma air winner safe smile region oil maximum gorilla process link aspect spoon junk crowd employ fury case join one"
	w := strings.Split(words, " ")

	
	mnPw := "mnemonicpasswordtest"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}

	wallet.SetDescription("wallet description")

	var a *Account
	for i := 0; i < 4; i++ {
		a = wallet.GenerateAccount(&wPw)
		if a == nil {
			t.Fatalf("GenerateAccount failed")
		}
	}


	if !wallet.DeleteAccount(a) {
		t.Fatalf("DeleteAccount failed")
	}

	k := "SAFWTGXVS7ELMNCXELFWCFZOPMHUZ5LXNBGUVRCY3FHLFPXK4QPXYP2X"
	a = wallet.AddRandomAccount(&k, &wPw)
	if a == nil {
		t.Fatalf("AddRandomAccount failed")
	}

	if a.SetMemoText("memo1") != nil {
		t.Fatalf("SetMemoText failed")
	}

	a.SetMemoId(1234)

	k = "SBQPDFUGLMWJYEYXFRM5TQX3AX2BR47WKI4FDS7EJQUSEUUVY72MZPJF"
	a = wallet.AddRandomAccount(&k, &wPw)
	if a == nil {
		t.Fatalf("AddRandomAccount failed")
	}
	a.SetDescription("Account desc 1")
	a.SetMemoId(958483)
	
	a = wallet.AddWatchingAccount("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS")
	if a == nil {
		t.Fatalf("AddWatchingAccount failed")
	}
	

	a = wallet.AddAddressBookAccount("GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4")
	if a == nil {
		t.Fatalf("AddAddressBookAccount failed")
	}

	as := wallet.AddAsset("GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4", "EURT")
	if as == nil {
		t.Fatalf("AddAsset failed")
	}

	if !wallet.DeleteAsset(as) {
		t.Fatalf("DeleteAsset failed")	
	}

	as1 := wallet.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "EURT")
	if as1 == nil {
		t.Fatalf("AddAsset failed")
	}

	as2 := wallet.AddAsset("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS", "USDT")
	if as2 == nil {
		t.Fatalf("AddAsset failed")
	}
	as2.SetDescription("asset description")

	tp1 := wallet.AddTradingPair(as1, as2)
	if tp1 == nil {
		t.Fatalf("AddTradingPair failed")
	}
	if tp1.SetDescription("trading pair description") != nil {
		t.Fatalf("trading pair: add description failed")
	}

	tp2 := wallet.AddTradingPair(as1, nil)
	if tp2 == nil {
		t.Fatalf("AddTradingPair failed")
	}

	tp3 := wallet.AddTradingPair(nil, as1)
	if tp3 == nil {
		t.Fatalf("AddTradingPair failed")
	}

	return wallet

}

func createWallet2(t *testing.T, wPw string) *Wallet {
	words := "merge silver adult unusual dilemma air winner safe smile region oil maximum gorilla process link aspect spoon junk crowd employ fury case join one"
	w := strings.Split(words, " ")

	
	mnPw := "mnemonicpasswordtest"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}	

	return wallet

}

func createWallet3(t *testing.T, wPw string) *Wallet {
	wallet := NewWallet(&wPw)

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}

	
	k := "SAFWTGXVS7ELMNCXELFWCFZOPMHUZ5LXNBGUVRCY3FHLFPXK4QPXYP2X"
	a := wallet.AddRandomAccount(&k, &wPw)
	if a == nil {
		t.Fatalf("AddRandomAccount failed")
	}
	a.SetDescription("Account desc 1")
	

	return wallet

}

// creates 100 accounts
func createWallet4(t *testing.T, wPw string) *Wallet {
	words := "merge silver adult unusual dilemma air winner safe smile region oil maximum gorilla process link aspect spoon junk crowd employ fury case join one"
	w := strings.Split(words, " ")

	
	mnPw := "mnemonicpasswordtest"

	wallet := NewWalletFromMnemonic(&wPw, w, &mnPw) 

	if wallet == nil {
		t.Logf("generate wallet from mnemonic failed")
		t.FailNow()
	}	

	for i := 0; i < 100; i++ {
		a := wallet.GenerateAccount(&wPw)
		if a == nil {
			t.Fatalf("GenerateAccount failed")
		}
		a.SetDescription(fmt.Sprintf("SEP005 Account %d", i+1))
		a.SetMemoText(fmt.Sprintf("memo %d", i+1))
		a.SetMemoId(1000)
	}

	return wallet

}

// Creates a wallet from mnemonic word list for 256bit entropy with empty menmonic pwassword from
// https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
func createWalletStd1(t *testing.T, wPw string) *Wallet {
	words := strings.Split("bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better", " ")


	mnPw := ""

	w := NewWalletFromMnemonic(&wPw, words, &mnPw) 

	if w == nil {
		t.Fatal("generate wallet from mnemonic failed")
	}

	return w
}

func compareAccounts(t *testing.T, verbose bool, pw1, pw2 string, a1, a2 *Account) {

	if a1.Type() != a2.Type() {
		t.Errorf("compareAccount: type mismatch")
	}

	if a1.Description() != a2.Description() {
		t.Errorf("compareAccount: type mismatch")
	}

	if a1.PublicKey() != a2.PublicKey() {
		t.Errorf("compareAccount: public key mismatch")
	}

	if a1.PrivateKey(&pw1) != a2.PrivateKey(&pw2) {
		t.Errorf("compareAccount: private key mismatch")
	}

	if a1.sep0005DerivationPath != a2.sep0005DerivationPath {
		t.Errorf("compareAccount: sep0005DerivationPath mismatch")
	}

	if a1.MemoText() != a2.MemoText() {
		t.Errorf("compareAccount: memo text mismatch")
	}

	ids1, id1 := a1.MemoId()
	ids2, id2 := a2.MemoId()

	if ids1 != ids2 || id1 != id2 {
		t.Errorf("compareAccount: memo id mismatch")
	}
	
	if verbose {
		t.Logf("Account: %s", a1.PublicKey())
		t.Logf("Account type: %d", a1.Type())
		t.Logf("Account description: %s", a1.Description())
		t.Logf("Account private key: %s", a1.PrivateKey(&pw1))
		t.Logf("Account sep0005DerivationPath: %s", a1.sep0005DerivationPath)
		t.Logf("Account memo text: %s", a1.MemoText())
		t.Logf("Account memo id: %t %d", ids1, id1)
	}
}

func compareAssets(t *testing.T, verbose bool, pw1, pw2 string, a1, a2 *Asset) {
	if a1.Description() != a2.Description() {
		t.Errorf("compareAsset: type mismatch")
	}

	if a1.Issuer() != a2.Issuer() {
		t.Errorf("compareAsset: issuer mismatch")
	}

	if a1.AssetId() != a2.AssetId() {
		t.Errorf("compareAsset: assetId mismatch")
	}

	tps1 := a1.TradingPairs()
	tps2 := a1.TradingPairs()

	if len(tps1) != len(tps2) {
		t.Errorf("compareAsset: linked trading pairs count mismatch")
	}

	for i, _ := range(tps1) {
		compareTradingPairs(t, verbose, tps1[i], tps2[i])
	}

	if verbose {
		t.Logf("Asset Issuer: %s", a1.Issuer())
		t.Logf("Asset ID: %s", a1.AssetId())
		t.Logf("Asset description: %s", a1.Description())
	}

}

func compareTradingPairs(t *testing.T, verbose bool, tp1, tp2 *TradingPair) {
	if tp1.Description() != tp2.Description() {
		t.Errorf("compareTradingPair: description mismatch")
	}

	issuer1 := ""
	issuer2 := ""
	id1 := "XLM"
	id2 := "XLM"

	if tp1.Asset1() != nil {
		issuer1 = tp1.Asset1().Issuer()
		id1 = tp1.Asset1().AssetId()
	}

	if tp2.Asset1() != nil {
		issuer2 = tp2.Asset1().Issuer()
		id2 = tp2.Asset1().AssetId()
	}

	
	if issuer1 != issuer2 || id1 != id2 {
		t.Errorf("compareTradingPair: asset 1 mismatch")
	}

	issuer1 = ""
	issuer2 = ""
	id1 = "XLM"
	id2 = "XLM"

	if tp1.Asset2() != nil {
		issuer1 = tp1.Asset2().Issuer()
		id1 = tp1.Asset2().AssetId()
	}

	if tp2.Asset2() != nil {
		issuer2 = tp2.Asset2().Issuer()
		id2 = tp2.Asset2().AssetId()
	}

	
	if issuer1 != issuer2 || id1 != id2 {
		t.Errorf("compareTradingPair: asset 2 mismatch")
	}

	if verbose {
		if tp1.Asset1() != nil {
			t.Logf("TradingPair Asset1 Issuer: %s", tp1.Asset1().Issuer())
			t.Logf("TradingPair Asset1 ID: %s", tp1.Asset1().AssetId())
		}
		if tp1.Asset2() != nil {
			t.Logf("TradingPair Asset2 Issuer: %s", tp1.Asset2().Issuer())
			t.Logf("TradingPair Asset2 ID: %s", tp1.Asset2().AssetId())
		}
		t.Logf("TradingPair description: %s", tp1.Description())
	}

}
	

func compareWallets(t *testing.T, verbose bool, pw1, pw2 string, w1, w2 *Wallet) {
	if w1.desc != w2.desc {
		t.Fatalf("verification of description failed")
	}

	key1 := deriveAesKey(&pw1)
	key2 := deriveAesKey(&pw2)
	
	seed1 := w1.decryptMasterSeed(key1)
	seed2 := w2.decryptMasterSeed(key2)
	if bytes.Compare(seed1, seed2) != 0 {
		t.Fatalf("verification of master seed failed")
	}

	seed1 = nil
	seed2 = nil

	if w1.bip39Seed != nil { 
		seed1 = w1.decryptBip39Seed(key1)
	}

	if w2.bip39Seed != nil { 
		seed2 = w2.decryptBip39Seed(key2)
	}

	if bytes.Compare(seed1, seed2) != 0 {
		t.Fatalf("verification of bip39 seed failed")
	}

	if w1.sep0005AccountCount != w2.sep0005AccountCount {
		t.Fatalf("verification of sep0005AccountCount failed")
	}

	accounts1 := w1.Accounts()
	accounts2 := w2.Accounts()
	l1 := len(accounts1) 
	l2 := len(accounts2)

	t.Logf("Account count: %d", l1)

	if l1 != l2 {
		t.Fatalf("verification of account count failed: %d vs %d", l1, l2)
	}

	for _, a1 := range accounts1 {
		a2 := w2.FindAccountByPublicKey(a1.PublicKey())
		if a2 == nil {
			t.Fatalf("account not found") 
		}
		compareAccounts(t, verbose, pw1, pw2, a1, a2)
	}


	accounts1 = w1.AddressBook()
	accounts2 = w2.AddressBook()
	l1 = len(accounts1) 
	l2 = len(accounts2)

	t.Logf("Address Book count: %d", l1)

	if l1 != l2 {
		t.Fatalf("verification of address book count failed: %d vs %d", l1, l2)
	}

	for _, a1 := range accounts1 {
		a2 := w2.FindAccountByPublicKey(a1.PublicKey())
		if a2 == nil {
			t.Fatalf("account not found") 
		}
		compareAccounts(t, verbose, pw1, pw2, a1, a2)
	}

	assets1 := w1.Assets()
	assets2 := w2.Assets()
	l1 = len(assets1)
	l2 = len(assets2)

	t.Logf("Asset count: %d", l1)
	
	if l1 != l2 {
		t.Fatalf("verification of asset count failed: %d vs %d", l1, l2)
	}

	for _, a1 := range assets1 {
		a2 := w2.FindAsset(a1.Issuer(), a1.AssetId())
		if a2 == nil {
			t.Fatalf("asset not found") 
		}
		compareAssets(t, verbose, pw1, pw2, a1, a2)
	}

	tps1 := w1.TradingPairs()
	tps2 := w2.TradingPairs()
	l1 = len(tps1)
	l2 = len(tps2)

	t.Logf("TradingPair count: %d", l1)
	
	if l1 != l2 {
		t.Fatalf("verification of trading pair count failed: %d vs %d", l1, l2)
	}

	for _, tp1 := range tps1 {
		var a1, a2 *Asset
		if tp1.Asset1() != nil {
			a1 = w2.FindAsset(tp1.Asset1().Issuer(), tp1.Asset1().AssetId())
		}
		if tp1.Asset2() != nil {
			a2 = w2.FindAsset(tp1.Asset2().Issuer(), tp1.Asset2().AssetId())
		}
		tp2 := w2.FindTradingPair(a1, a2)
		if tp2 == nil {
			t.Fatalf("trading pair not found") 
		}
		compareTradingPairs(t, verbose, tp1, tp2)
	}
}

func TestIO1(t *testing.T) {
	pw := "gBCdqqYVvCmJJAQOhtuwme8vvGArKDov"

	w := NewWallet(&pw)
	
	w.desc = "Test"

	data := w.ExportBase64()
	
	if data == "" {
		t.Fatalf("write to buffer failed")
	}

	t.Logf("data: %s\n", data)

	w1, err := ImportBase64(data)

	if err != nil {
		t.Fatalf("read from buffer failed: %s", err.Error() )
	}

	compareWallets(t, true, pw, pw, w, w1)

}

func TestIO2(t *testing.T) {
	pw := "stellarwalletpw"
	w := createWallet1(t, pw)


	data := w.ExportBase64()
	
	if data == "" {
		t.Fatalf("write to buffer failed")
	}

	t.Logf("data: %s\n", data)

	w1, err := ImportBase64(data)

	if err != nil {
		t.Fatalf("read from buffer failed: %s", err.Error() )
	}
	
	compareWallets(t, true, pw, pw, w, w1)
	
}

func TestIO3(t *testing.T) {
	pw := "stellarwalletpw"
	w := createWallet2(t, pw)


	data := w.ExportBase64()
	
	if data == "" {
		t.Fatalf("write to buffer failed")
	}

	t.Logf("data: %s\n", data)

	w1, err := ImportBase64(data)

	if err != nil {
		t.Fatalf("read from buffer failed: %s", err.Error() )
	}
	
	compareWallets(t, true, pw, pw, w, w1)
	
}

func TestIO4(t *testing.T) {
	pw := "stellarwalletpw"
	w := createWallet3(t, pw)


	data := w.ExportBase64()
	
	if data == "" {
		t.Fatalf("write to buffer failed")
	}

	t.Logf("data: %s\n", data)

	w1, err := ImportBase64(data)

	if err != nil {
		t.Fatalf("read from buffer failed: %s", err.Error() )
	}
	
	compareWallets(t, true, pw, pw, w, w1)
	
}


func TestIO5(t *testing.T) {
	pw := "stellarwalletpw"
	w := createWallet4(t, pw)


	data := w.ExportBase64()
	
	if data == "" {
		t.Fatalf("write to buffer failed")
	}

	//t.Logf("data: %s\n", data)

	w1, err := ImportBase64(data)

	if err != nil {
		t.Fatalf("read from buffer failed: %s", err.Error() )
	}
	
	compareWallets(t, false, pw, pw, w, w1)
	
}

