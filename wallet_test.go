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

	words := w.GetBip39Mnemonic(&pw)

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

	if w2.GenerateSep0005Account(&pw2) == nil {
		t.Fatalf("GenerateSep0005Account failed")
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

	wordsFromSeed := wallet.GetBip39Mnemonic(&wPw)

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

	wordsFromSeed := wallet.GetBip39Mnemonic(&wPw)

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
		a := wallet.GenerateSep0005Account(&wPw)

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

	wordsFromSeed := wallet.GetBip39Mnemonic(&wPw)

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
		a := wallet.GenerateSep0005Account(&wPw)

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

	wordsFromSeed := wallet.GetBip39Mnemonic(&wPw)

	if wordsFromSeed == nil {
		t.Logf("retrieving mnemonic word list from seed failed")
		t.FailNow()
	}

	t.Logf("Words from seed: %s", strings.Join(wordsFromSeed, " ") )

	if strings.Join(wordsFromSeed, " ") != words {
		t.Logf("word lists do not match")
	}

}

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
		a := wallet.GenerateSep0005Account(&wPw)

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

	wordsFromSeed := wallet.GetBip39Mnemonic(&wPw)

	if wordsFromSeed == nil {
		t.Logf("retrieving mnemonic word list from seed failed")
		t.FailNow()
	}

	t.Logf("Words from seed: %s", strings.Join(wordsFromSeed, " ") )

	if strings.Join(wordsFromSeed, " ") != words {
		t.Logf("word lists do not match")
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

	accounts := w.GetAccounts()
	
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

	accounts := w.GetAddressBook()
	
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

	accounts = w.GetAddressBook()
	
	if len(accounts) != 0 {
		t.Fatalf("unexpected account count")
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

	var a *Account
	for i := 0; i < 4; i++ {
		a = wallet.GenerateSep0005Account(&wPw)
		if a == nil {
			t.Fatalf("GenerateSep0005Account failed")
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

	k = "SBQPDFUGLMWJYEYXFRM5TQX3AX2BR47WKI4FDS7EJQUSEUUVY72MZPJF"
	a = wallet.AddRandomAccount(&k, &wPw)
	if a == nil {
		t.Fatalf("AddRandomAccount failed")
	}
	a.SetDescription("Account desc 1")
	
	a = wallet.AddWatchingAccount("GCUDW6ZF5SCGCMS3QUTELZ6LSAH6IVVXNRPRLAUNJ2XYLCA7KH7ZCVQS")
	if a == nil {
		t.Fatalf("AddWatchingAccount failed")
	}
	

	a = wallet.AddAddressBookAccount("GDHX4LU6YBSXGYTR7SX2P4ZYZSN24VXNJBVAFOB2GEBKNN3I54IYSRM4")
	if a == nil {
		t.Fatalf("AddAddressBookAccount failed")
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
		a := wallet.GenerateSep0005Account(&wPw)
		if a == nil {
			t.Fatalf("GenerateSep0005Account failed")
		}
		a.SetDescription(fmt.Sprintf("SEP005 Account %d", i+1))
	}

	return wallet

}

func compareAccounts(t *testing.T, verbose bool, pw1, pw2 string, a1, a2 *Account) {

	if a1.Type() != a2.Type() {
		t.Errorf("compareAccount: type mismatch")
	}

	if a1.GetDescription() != a2.GetDescription() {
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
	
	if verbose {
		t.Logf("Account: %s", a1.PublicKey())
		t.Logf("Account type: %d", a1.Type())
		t.Logf("Account description: %s", a1.GetDescription())
		t.Logf("Account private key: %s", a1.PrivateKey(&pw1))
		t.Logf("Account sep0005DerivationPath: %s", a1.sep0005DerivationPath)
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

	accounts1 := w1.GetAccounts()
	accounts2 := w2.GetAccounts()
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


	accounts1 = w1.GetAddressBook()
	accounts2 = w2.GetAddressBook()
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

