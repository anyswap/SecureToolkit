package secure_channel

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
)

func BigInt2HexString(integer *big.Int, byteLen int) (string, error) {

	formatStr := "%0" + strconv.Itoa(byteLen * 2) + "s"
	hexStr := fmt.Sprintf(formatStr, integer.Text(16))

	if len(hexStr) > byteLen * 2 {
		return "", errors.New("failed to convert big.Int to hex string, larger than " + strconv.Itoa(byteLen) + " bytes")
	}

	return hexStr, nil
}

func HexString2BigInt(hexStr string) (*big.Int, error) {

	bigInt, result := new(big.Int).SetString(hexStr, 16)
	if !result {
		return nil, errors.New("failed to convert hex string to big.Int, invalid hex string")
	}

	return bigInt, nil
}

func BytesArray2HexString(arr []byte) string {
	// the result string can start with 0
	return hex.EncodeToString(arr)
}

func HexString2BytesArray(hexStr string) ([]byte, error) {

	if len(hexStr) % 2 == 1 {
		return nil, errors.New("failed to convert hex string to byte array, invalid hex string with odd length")
	} 

	arr, err := hex.DecodeString(hexStr)

	if err != nil {
		return nil, err
	}

	return arr, nil
}
