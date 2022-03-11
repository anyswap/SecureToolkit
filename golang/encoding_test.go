package secure_channel

import(
	"testing"
	"math/big"
)

func TestBigInt2HexString (t *testing.T) {

	one := new(big.Int).SetInt64(1)
	oneHex, zErr := BigInt2HexString(one, 2)

	if zErr != nil || oneHex != "0001" {
		t.Fail()
	}

	w, _ := new(big.Int).SetString("10000", 16)
	tHex, tErr := BigInt2HexString(w, 3)

	if tErr != nil || tHex != "010000" {
		t.Fail()
	}


	_, tErr = BigInt2HexString(w, 2)

	if tErr == nil {
		t.Fail()
	}

}

func TestHexString2BigInt(t *testing.T) {

	zero := new(big.Int).SetInt64(0)

	zeroHex := "0"
	z, zErr := HexString2BigInt(zeroHex)

	if zErr != nil || z.Cmp(zero) != 0 {
		t.Fail()
	}

	hex := "100not_valid"
	_, wErr := HexString2BigInt(hex)

	if wErr == nil {
		t.Fail()
	}
}

func TestBytesArray2HexString(t *testing.T) {

	bArr := []byte("0123")
	bArrHex := BytesArray2HexString(bArr)

	if bArrHex != "30313233" {
		t.Fail()
	}

}

func TestHexString2BytesArray(t *testing.T) {

	hexStr := "30313233"
	bArr := []byte("0123")

	bArr2, bErr := HexString2BytesArray(hexStr)

	if bErr != nil || bArr2[0] != bArr[0] || bArr2[1] != bArr[1] || bArr2[2] != bArr[2] || bArr2[3] != bArr[3] {
		t.Fail()
	}

	_, bErr = HexString2BytesArray(hexStr[1:])

	if bErr == nil {
		t.Fail()
	}

}
