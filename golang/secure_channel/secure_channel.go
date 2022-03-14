package secure_channel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"io"
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
)

type SignedData struct {
	Data string
	Hash string // hash of data, length 32 bytes in hex string
	Sig	string // ieee-p1363 format, a.k.a r||s, length 64 bytes in hex string
	IdFrom string // optional, identifier of sender
}

type EncSignedData struct {
	DataEnc string // IV (16 bytes), R (64 bytes) and ciphertext of data in hex string, encrypted by ecies (AES CTR mode)
	Hash string // hash of data, length 32 bytes in hex string
	Sig	string // ieee-p1363 format, a.k.a r||s, length 64 bytes in hex string
	IdFrom string // optional, identifier of sender
}

// curve prime256v1
type ECKeyPair struct{
	PublicKey string // format x || y, 64 bytes in hex string
	PrivateKey string // 32 bytes in hex string
}

func GenerateECKeyPair() (ecKeyPair *ECKeyPair, err error) {

	keyPair, errKeyGen := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if errKeyGen != nil {
		return nil, errKeyGen
	}

	xStr, errXStr := BigInt2HexString(keyPair.X, 32)
	yStr, errYStr := BigInt2HexString(keyPair.Y, 32)

	skStr, errSkStr := BigInt2HexString(keyPair.D, 32)

	if errXStr != nil || errYStr != nil || errSkStr != nil {
		return nil, errors.New("failed to format the EC keypair to hex string")
	}

	ecKeyPair = &ECKeyPair{
		PublicKey: xStr + yStr,
		PrivateKey: skStr,
	}

	return
}

func CalSignedData(selfSkHexStr string, data string) (signedData *SignedData, err error) {

	hash := sha256.Sum256([]byte(data))
	hashHexStr := BytesArray2HexString(hash[:])

	sk, errSk := recoverPrivateKey(selfSkHexStr)
	if errSk != nil {
		return nil, errSk
	}

	r, s, errSig := ecdsa.Sign(rand.Reader, sk, hash[:])
	if errSig != nil {
		return nil, errors.New("failed to compute the signature, " + errSig.Error())
	}

	rStr, errR := BigInt2HexString(r, 32)
	sStr, errS := BigInt2HexString(s, 32)

	if errR != nil || errS != nil {
		return nil, errors.New("failed to format the signature to hex string")
	}
	
	signedData = &SignedData{
		Data: data,
		Hash: hashHexStr,
		Sig: rStr + sStr,
	}
	
	return
}

func VerifySignedData(fromPkHexStr string, signedData *SignedData) (data string, err error) {

	hashCal := sha256.Sum256([]byte(signedData.Data))
	hashCalHexStr := BytesArray2HexString(hashCal[:])

	// verify hash

	if hashCalHexStr != signedData.Hash {
		return "", errors.New("invalid data, NOT pass hash validation")
	}

	pk, errPk := recoverPublicKey(fromPkHexStr)
	if errPk != nil {
		return "", errPk
	}

	if len(signedData.Sig) != 128 {
		return "", errors.New("invalid signature, should in ieee-p1363 format, a.k.a. r || s with length 64 bytes")
	}

	rBigInt, errR := HexString2BigInt(signedData.Sig[:64])
	sBigInt, errS := HexString2BigInt(signedData.Sig[64:])

	if errR != nil || errS != nil {
		return "", errors.New("invalid signature, failed to convert the hex string to big.Int")
	}

	// verify signature

	result := ecdsa.Verify(pk, hashCal[:], rBigInt, sBigInt)
	if !result {
		return "", errors.New("invalid signature, NOT pass signature validation")
	}

	return signedData.Data, nil
}

func CalEncSignedData(selfSkHexStr string, toPkHexStr string, data string) (encSignedData *EncSignedData, err error) {

	signedData, errSigned := CalSignedData(selfSkHexStr, data)
	if errSigned != nil {
		return nil, errSigned
	}

	pk, errPk := recoverPublicKey(toPkHexStr)
	if errPk != nil {
		return nil, errPk
	}

	r, errR := randomInt(32)
	iv, errIv := randomBytes(16)

	if errR != nil || errIv != nil {
		return nil, errors.New("failed to get random big.Int")
	}

	ivHexStr := BytesArray2HexString(iv)

	r = new(big.Int).Mod(r, elliptic.P256().Params().N)
	rPKx, _ := elliptic.P256().ScalarMult(pk.X, pk.Y, r.Bytes())
	Rx, Ry := elliptic.P256().ScalarBaseMult(r.Bytes())

	RxHexStr, errRx := BigInt2HexString(Rx, 32)
	RyHexStr, errRy := BigInt2HexString(Ry, 32)

	if errRx != nil || errRy != nil {
		return nil, errors.New("failed to format the R point to hex string")
	}

	// AES key: hash(rPKx), (rPKx, rPKy) = r * pk = sk * R

	keyAes := sha256.Sum256(rPKx.Bytes())

	// AES CTR encrypt

	aesBlock, errAes := aes.NewCipher(keyAes[:])
	if errAes != nil {
		return nil, errors.New("failed to initialize the AES encryption")
	}

	ciphertextBytes := make([]byte, len([]byte(data)))

	stream := cipher.NewCTR(aesBlock, iv)
	stream.XORKeyStream(ciphertextBytes, []byte(data))

	ciphertextHexStr := BytesArray2HexString(ciphertextBytes)

	encSignedData = &EncSignedData{
		DataEnc: ivHexStr + RxHexStr + RyHexStr + ciphertextHexStr,
		Hash: signedData.Hash,
		Sig: signedData.Sig,
	}

	return
}

func VerifyEncSignedData(selfSkHexStr string, fromPkHexStr string, encSignedData *EncSignedData) (data string, err error) {

	iv, errIv := HexString2BytesArray(encSignedData.DataEnc[:32])
	if errIv != nil {
		return "", errors.New("failed to get IV from encrypted data")
	}

	Rx, errRx := HexString2BigInt(encSignedData.DataEnc[32:96])
	Ry, errRy := HexString2BigInt(encSignedData.DataEnc[96:160])

	if errRx != nil || errRy != nil {
		return "", errors.New("failed to format hex string to R point")
	}

	skBitInt, errSk := HexString2BigInt(selfSkHexStr)
	if errSk != nil {
		return "", errors.New("failed to format the sk hex string to big.Int, " + errSk.Error())
	}

	rPKx, _ := elliptic.P256().ScalarMult(Rx, Ry, skBitInt.Bytes())

	// AES key: hash(x), (x, y) = r * pk = sk * R
	
	keyAes := sha256.Sum256(rPKx.Bytes())

	// AES CTR decrypt
	// note: decrypt always success, however is not the real plaintext with wrong selfSkHexStr

	aesBlock, errAes := aes.NewCipher(keyAes[:])
	if errAes != nil {
		return "", errors.New("failed to initialize the AES decryption")
	}

	ciphertextBytes, errCipher := HexString2BytesArray(encSignedData.DataEnc[160:])
	if errCipher != nil {
		return "", errors.New("failed to format the cipher in hex string to byte array, " + errCipher.Error())
	}

	plaintextBytes := make([]byte, len(ciphertextBytes))

	stream := cipher.NewCTR(aesBlock, iv)
	stream.XORKeyStream(plaintextBytes, ciphertextBytes)

	dataDecrypt := string(plaintextBytes[:])

	// verify hash and signature

	signedData := &SignedData{
		Data: dataDecrypt,
		Hash: encSignedData.Hash,
		Sig: encSignedData.Sig,
	}

	return VerifySignedData(fromPkHexStr, signedData)
}


func recoverPrivateKey(hexStr string) (*ecdsa.PrivateKey, error) {

	skBigInt, errSk := HexString2BigInt(hexStr)

	if errSk != nil {
		return nil, errors.New("failed to get private key from hex string, " + errSk.Error())
	}

	sk := new(ecdsa.PrivateKey)
	sk.PublicKey.Curve = elliptic.P256()
	sk.D = skBigInt
	sk.PublicKey.X, sk.PublicKey.Y = elliptic.P256().ScalarBaseMult(skBigInt.Bytes())

	return sk, nil
}

func recoverPublicKey(hexStr string) (*ecdsa.PublicKey, error) {

	if len(hexStr) != 128 {
		return nil, errors.New("failed to get public key from hex string, invalid public key hex string (x || y format), length should be 64 bytes")
	}

	XBigInt, errX := HexString2BigInt(hexStr[:64])
	YBigInt, errY := HexString2BigInt(hexStr[64:])

	if errX != nil || errY != nil {
		return nil, errors.New("failed to get public key from hex string")
	}

	pk := new(ecdsa.PublicKey)
	pk.Curve = elliptic.P256()
	pk.X, pk.Y = XBigInt, YBigInt

	return pk, nil
}

func randomInt(byteLen int) (*big.Int, error) {

	b := make([]byte, byteLen)
	
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)

	return k, nil
}

func randomBytes(byteLen int) ([]byte, error) {

	b := make([]byte, byteLen)
	
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
