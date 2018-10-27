package stellarwallet

import(
	"errors"
	"fmt"
	"io"
	"bytes"
	"encoding/binary"
	"crypto/sha1"	
	"crypto/hmac"
	"compress/gzip"

	//"encoding/hex"

)

const maxLen = 65535
const tagWalletDesc = 1
const tagWalletMasterSeed = 2
const tagWalletBip39Seed = 3
const tagWalletSep0005AccountCount = 4
const tagWalletSignature = 50
const tagWalletVersion = 51
const tagWalletFlags = 52

const tagAccount = 5
const tagAccountDesc = 6
const tagAccountType = 7
const tagAccountPublicKey = 8
const tagAccountPrivateKey = 9
const tagAccountSep005DerivationPath = 10
const tagAccountMemoText = 11
const tagAccountMemoId = 12
const tagAccountSignature = 13

const tagAsset = 20
const tagAssetDesc = 21
const tagAssetIssuer = 22
const tagAssetAssetId = 23
const tagAssetSignature = 24

const tagTradingPair = 30
const tagTradingPairDesc = 31
const tagTradingPairAsset1 = 32
const tagTradingPairAsset2 = 33
const tagTradingPairSignature = 34

const tagWalletStart = 100
const tagWalletEnd = 101


func writeUint16(w io.Writer, data uint16) {
	err := binary.Write(w, binary.BigEndian, data)
	if err != nil {
		panic("failed writing integer to buffer: " + err.Error())
	}
}

func readUint16(r io.Reader) (data uint16, err error) {
	var d uint16
	
	err = binary.Read(r, binary.BigEndian, &d)

	if err != nil {
		err = errors.New("failed to read from buffer: " + err.Error())
	}

	return d, err
}

func writeUint64(w io.Writer, data uint64) {
	err := binary.Write(w, binary.BigEndian, data)
	if err != nil {
		panic("failed writing integer to buffer: " + err.Error())
	}
}

func readUint64(r io.Reader) (data uint64, err error) {
	var d uint64
	
	err = binary.Read(r, binary.BigEndian, &d)

	if err != nil {
		err = errors.New("failed to read from buffer: " + err.Error())
	}

	return d, err
}

func writeBytes(w io.Writer, buf []byte) {
	count := len(buf) 

	if count > maxLen {
		panic("buffer too big")
	}

	writeUint16(w, uint16(count))

	n, err := w.Write(buf)
	
	if n != count {
		if err != nil {
			panic("failed writing byte data to buffer: " + err.Error())
		} else {
			panic("failed writing byte data to buffer")
		}
	}
}

func readBytes(r io.Reader) (buf []byte, err error) {
	var count int

	d, err := readUint16(r)

	if err != nil {
		return nil, err
	}

	count = int(d)

	//fmt.Printf("readBytes: count: %d\n", count)

	buf = make([]byte, count)

	n, err := r.Read(buf)

	if n != count {
		if err != nil {
			return nil, errors.New("failed reading byte data from buffer: " + err.Error())
		} else {
			return nil, errors.New("failed reading byte data from buffer")
		}
	}

	err = nil

	return
}

func writeString(w io.Writer, s string) {
	writeBytes(w, []byte(s))
}

func readString(r io.Reader) (s string, err error) {
	buf, err := readBytes(r)

	if err != nil {
		return "", err
	} else {
		return string(buf), nil
	}
}

func writeTag(w io.Writer, tag byte) {
	buf := []byte{ tag }

	n, err := w.Write(buf)
	
	if n != 1 {
		if err != nil {
			panic("failed writing tag to buffer: " + err.Error())
		} else {
			panic("failed writing tag to buffer")
		}
	}
}

func readTag(r io.Reader) (tag byte, err error) {
	buf := make([]byte, 1)

	n, err := r.Read(buf)

	if n != 1 {
		if err != nil {
			return 0, errors.New("failed reading tag from buffer: " + err.Error())
		} else {
			return 0, errors.New("failed reading tag from buffer")
		}
	}

	//fmt.Printf("Tag: %d\n", buf[0])

	return buf[0], nil
}

func (w *Wallet) writeToBuffer() []byte {
	buf := new(bytes.Buffer)

	writeTag(buf, tagWalletStart)

	writeTag(buf, tagWalletVersion)
	writeUint16(buf, walletVersion)

	writeTag(buf, tagWalletFlags)
	writeUint64(buf, uint64(w.flags))

	if w.desc != "" {
		writeTag(buf, tagWalletDesc)
		writeString(buf, w.desc)
	}

	writeTag(buf, tagWalletMasterSeed)
	writeBytes(buf, w.masterSeed)

	if w.bip39Seed != nil {
		writeTag(buf, tagWalletBip39Seed)
		writeBytes(buf, w.bip39Seed)

		writeTag(buf, tagWalletSep0005AccountCount)
		writeUint16(buf, w.sep0005AccountCount)
	}

	writeTag(buf, tagWalletSignature)
	writeBytes(buf, w.signature)

	for _, a := range w.accounts {

		if a.active {
			writeTag(buf, tagAccount)

			if a.desc != "" {
				writeTag(buf, tagAccountDesc)
				writeString(buf, a.desc)
			}
			
			writeTag(buf, tagAccountType)
			writeUint16(buf, a.accountType)
			
			writeTag(buf, tagAccountPublicKey)
			writeString(buf, a.publicKey)
			
			if a.privateKey != nil {
				writeTag(buf, tagAccountPrivateKey)
				writeBytes(buf, a.privateKey)
			}

			if len(a.sep0005DerivationPath) > 0 {
				writeTag(buf, tagAccountSep005DerivationPath)
				writeString(buf, a.sep0005DerivationPath)
			}

			if a.memoText != "" {
				writeTag(buf, tagAccountMemoText)
				writeString(buf, a.memoText)
			}

			if a.memoIdSet {
				writeTag(buf, tagAccountMemoId)
				writeUint64(buf, a.memoId)
			}

			if a.signature != nil {
				writeTag(buf, tagAccountSignature)
				writeBytes(buf, a.signature)
			}
		}
	}

	for _, a := range w.assets {
		if a.active {
			writeTag(buf, tagAsset)

			if a.desc != "" {
				writeTag(buf, tagAssetDesc)
				writeString(buf, a.desc)
			}

			writeTag(buf, tagAssetIssuer)
			writeString(buf, a.issuer)
			
			writeTag(buf, tagAssetAssetId)
			writeString(buf, a.assetId)

			if a.signature != nil {
				writeTag(buf, tagAssetSignature)
				writeBytes(buf, a.signature)
			}
		}
	}

	for _, tp := range w.tradingPairs {
		if tp.active {
			writeTag(buf, tagTradingPair)

			if tp.desc != "" {
				writeTag(buf, tagTradingPairDesc)
				writeString(buf, tp.desc)
			}

			if tp.asset1 != nil {
				writeTag(buf, tagTradingPairAsset1)
				writeString(buf, tp.asset1.issuer)
				writeString(buf, tp.asset1.assetId)
			}

			if tp.asset2 != nil {
				writeTag(buf, tagTradingPairAsset2)
				writeString(buf, tp.asset2.issuer)
				writeString(buf, tp.asset2.assetId)
			}

			if tp.signature != nil {
				writeTag(buf, tagTradingPairSignature)
				writeBytes(buf, tp.signature)
			}
		}
	}

	writeTag(buf, tagWalletEnd)

	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())

	mac := hmac.New(sha1.New, []byte(stellarwalletSeed))
	_, err := mac.Write(data)
	if err != nil {
		panic(err)
	}
	sum := mac.Sum(nil)

	data = append(data, sum...)

	return data
}

func (w *Wallet) readFromBuffer(buf []byte) error {

	// verify checksum
	mac := hmac.New(sha1.New, []byte(stellarwalletSeed))

	if len(buf) < mac.Size() {
		return errors.New("reader: checksum failed")
	}

	_, err := mac.Write(buf[:len(buf)-mac.Size()])
	if err != nil {
		panic(err)
	}
	sum := mac.Sum(nil)

	if !hmac.Equal(sum, buf[len(buf)-mac.Size():]) {
		return errors.New("reader: checksum failed")
	}

	// parse buffer
	var ac *Account
	var as *Asset
	var tp *TradingPair
	var wversion uint16

	wversion = 0

	r := bytes.NewReader(buf)

	tag, err := readTag(r)
	if err != nil { return err }

	if tag != tagWalletStart {
		return errors.New("missing start tag")
	}

	for stop:= false; !stop;  {
		tag, err := readTag(r)
		if err != nil { return err }

		switch tag {
		case tagWalletVersion:
			wversion, err = readUint16(r)

		case tagWalletFlags:
			d, err := readUint64(r)
			if err != nil { return err }
			w.flags = WalletFlags(d)

		case tagWalletDesc:
			s, err := readString(r)
			if err != nil { return err }
			w.desc = s

		case tagWalletMasterSeed:
			buf, err := readBytes(r)
			if err != nil { return err }
			w.masterSeed = buf

		case tagWalletBip39Seed:
			buf, err := readBytes(r)
			if err != nil { return err }
			w.bip39Seed = buf
			
		case tagWalletSep0005AccountCount:
			d, err := readUint16(r)
			if err != nil { return err }
			w.sep0005AccountCount = d

		case tagWalletSignature:
			buf, err := readBytes(r)
			if err != nil { return err }
			w.signature = buf

		case tagAccount:
			ac = w.newAccount()
			ac.active = true

		case tagAccountDesc:
			if ac == nil { return errors.New("unexpected account tag") }
			s, err := readString(r)
			if err != nil { return err }
			ac.desc = s
				
		case tagAccountType:
			if ac == nil { return errors.New("unexpected account tag") }
			d, err := readUint16(r)
			if err != nil { return err }
			ac.accountType = d

		case tagAccountPublicKey:
			if ac == nil { return errors.New("unexpected account tag") }
			s, err := readString(r)
			if err != nil { return err }
			ac.publicKey = s

		case tagAccountPrivateKey:
			if ac == nil { return errors.New("unexpected account tag") }
			buf, err := readBytes(r)
			if err != nil { return err }
			ac.privateKey = buf

		case tagAccountSep005DerivationPath:
			if ac == nil { return errors.New("unexpected account tag") }
			s, err := readString(r)
			if err != nil { return err }
			ac.sep0005DerivationPath = s

		case tagAccountMemoText:
			if ac == nil { return errors.New("unexpected account tag") }
			s, err := readString(r)
			if err != nil { return err }
			ac.memoText = s

		case tagAccountMemoId:
			if ac == nil { return errors.New("unexpected account tag") }
			id, err := readUint64(r)
			if err != nil { return err }
			ac.memoId = id
			ac.memoIdSet = true

		case tagAccountSignature:
			if ac == nil { return errors.New("unexpected account tag") }
			buf, err := readBytes(r)
			if err != nil { return err }
			ac.signature = buf

		case tagAsset:
			as = w.newAsset()
			as.active = true

		case tagAssetDesc:
			if as == nil { return errors.New("unexpected asset tag") }
			s, err := readString(r)
			if err != nil { return err }
			as.desc = s

		case tagAssetIssuer:
			if as == nil { return errors.New("unexpected asset tag") }
			s, err := readString(r)
			if err != nil { return err }
			as.issuer = s

		case tagAssetAssetId:
			if as == nil { return errors.New("unexpected asset tag") }
			s, err := readString(r)
			if err != nil { return err }
			as.assetId = s

		case tagAssetSignature:
			if as == nil { return errors.New("unexpected asset tag") }
			buf, err := readBytes(r)
			if err != nil { return err }
			as.signature = buf

		case tagTradingPair:
			tp = w.newTradingPair()
			tp.active = true

		case tagTradingPairDesc:
			if tp == nil { return errors.New("unexpected trading pair tag") }
			s, err := readString(r)
			if err != nil { return err }
			tp.desc = s

		case tagTradingPairAsset1:
			if tp == nil { return errors.New("unexpected trading pair tag") }
			issuer, err := readString(r)
			if err != nil { return err }
			id, err := readString(r)
			if err != nil { return err }
			tp.asset1 = w.FindAsset(issuer, id)
			if tp.asset1 == nil { return errors.New("trading pair asset not found") }
			tp.asset1.linkTradingPair(tp)

		case tagTradingPairAsset2:
			if tp == nil { return errors.New("unexpected trading pair tag") }
			issuer, err := readString(r)
			if err != nil { return err }
			id, err := readString(r)
			if err != nil { return err }
			tp.asset2 = w.FindAsset(issuer, id)
			if tp.asset2 == nil { return errors.New("trading pair asset not found") }
			tp.asset2.linkTradingPair(tp)

		case tagTradingPairSignature:
			if tp == nil { return errors.New("unexpected trading pair tag") }
			buf, err := readBytes(r)
			if err != nil { return err }
			tp.signature = buf

		case tagWalletEnd:
			stop = true

		default:
			return errors.New(fmt.Sprintf("invalid tag found: %x", tag) )
		}

		w.migrateWallet(wversion)
	}


	return nil
}

func (w *Wallet)migrateWallet(fromVersion uint16) {
	// nothing to do for now
}

func (w *Wallet) writeToBufferCompressed() []byte {
	buf := w.writeToBuffer()

	bufComp := new(bytes.Buffer)

	compress, err := gzip.NewWriterLevel(bufComp, gzip.BestCompression)
	if err != nil { panic("compressing failed: " + err.Error()) }

	n, err := compress.Write(buf)
	if err != nil { panic("compressing failed: " + err.Error()) }
	if n != len(buf) { panic("compressing failed: " + err.Error()) }
		
	err = compress.Close()
	if err != nil { panic("compressing failed: " + err.Error()) }

	return bufComp.Bytes()
}


func (w *Wallet) readFromBufferCompressed(buf []byte) error {
	r := bytes.NewReader(buf)
	
	decompress, err := gzip.NewReader(r)
	if err != nil { return errors.New("de-compressing failed: " + err.Error()) }
	
	blkLen := 100

	tmp := make([]byte, blkLen)
	var result []byte

	for cont := true; cont; {
		n, err := decompress.Read(tmp)
		if n != 0 {
			//fmt.Printf("Decompress tmp: %s\n", hex.EncodeToString(tmp[:n]))
			result = append(result, tmp[:n]...)
		} else {
			if err == nil || err == io.EOF {
				cont = false
			} else {
				return errors.New("de-compressing failed: " + err.Error())
			}
		}
	}
	err = decompress.Close()
	if err != nil { return errors.New("de-compressing failed: " + err.Error()) }

	//fmt.Printf("Decompress: %s\n", hex.EncodeToString(result))
	
	return w.readFromBuffer(result)
}
