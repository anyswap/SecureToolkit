package secure_channel

import (
	"testing"
)

const data = "Test data 1	Test data 2	Test data 3	Test data 4	Test data 5	Test data 6	Test data 7	Test data 8	Test data 9	Test data 10	Test data 11	Test data 12	Test data 13	Test data 14	Test data 15	Test data 16	Test data 17	Test data 18	Test data 19	Test data 20	Test data 21	Test data 22	Test data 23	Test data 24	Test data 25	Test data 26"

func BenchmarkGenerateECKeyPair(b *testing.B) {

	for i := 0; i < b.N; i++ {

		keyPair, err := GenerateECKeyPair()
		if err != nil {
			b.Fail()
		}

		b.Log((len(keyPair.PrivateKey) + len(keyPair.PublicKey)) == 192) // pk hex str, 128; sk hex str, 64

	}

}


func BenchmarkVerifySignedData(b *testing.B) {

	keyPair, _ := GenerateECKeyPair()

	for i := 0; i < b.N; i++ {

		signedData, sErr := CalSignedData(keyPair.PrivateKey, data)
		if sErr != nil {
			b.Fail()
		}

		recoverData, vErr := VerifySignedData(keyPair.PublicKey, signedData)
		if vErr != nil {
			b.Fail()
		}

		b.Log(recoverData == data)
	}
	
}

func BenchmarkVerifyChangedSignedData(b *testing.B) {

	keyPair, _ := GenerateECKeyPair()
	bKeyPair, _ := GenerateECKeyPair()

	for i := 0; i < b.N; i++ {

		signedData, sErr := CalSignedData(keyPair.PrivateKey, data)
		if sErr != nil {
			b.Fail()
		}

		_, vsErr := VerifySignedData(keyPair.PublicKey, signedData)
		if vsErr != nil {
			b.Fail()
		}

		// change pk
		vData, vErr := VerifySignedData(bKeyPair.PublicKey, signedData)
		if vErr == nil ||  vData != ""{
			b.Fail()
		}

		// change hash
		changedSignedData := *signedData
		changedSignedData.Hash = changedSignedData.Hash[4:] + "0000"

		vData, vErr = VerifySignedData(keyPair.PublicKey, &changedSignedData)
		if vErr == nil ||  vData != ""{
			b.Fail()
		}

		// change sig
		changedSignedData = *signedData
		changedSignedData.Sig = changedSignedData.Sig[4:] + "0000"

		vData, vErr = VerifySignedData(keyPair.PublicKey, &changedSignedData)
		if vErr == nil ||  vData != ""{
			b.Fail()
		}

		// change data
		changedSignedData = *signedData
		changedSignedData.Data = changedSignedData.Data[4:] + "0000"

		vData, vErr = VerifySignedData(keyPair.PublicKey, &changedSignedData)
		if vErr == nil ||  vData != ""{
			b.Fail()
		}

	}
	
}

func BenchmarkVerifyEncSignedData(b *testing.B) {

	aKeyPair, _ := GenerateECKeyPair()
	bKeyPair, _ := GenerateECKeyPair()

	for i := 0; i < b.N; i++ {

		signedData, sErr := CalEncSignedData(aKeyPair.PrivateKey, bKeyPair.PublicKey, data)
		if sErr != nil {
			b.Fail()
		}

		recoverData, vErr := VerifyEncSignedData(bKeyPair.PrivateKey, aKeyPair.PublicKey, signedData)
		if vErr != nil {
			b.Fail()
		}

		b.Log(recoverData == data)
	}
	
}

func BenchmarkVerifyChangedEncSignedData(b *testing.B) {

	aKeyPair, _ := GenerateECKeyPair()
	bKeyPair, _ := GenerateECKeyPair()
	cKeyPair, _ := GenerateECKeyPair()

	for i := 0; i < b.N; i++ {

		signedData, sErr := CalEncSignedData(aKeyPair.PrivateKey, bKeyPair.PublicKey, data)
		if sErr != nil {
			b.Fail()
		}

		_, vsErr := VerifyEncSignedData(bKeyPair.PrivateKey, aKeyPair.PublicKey, signedData)
		if vsErr != nil {
			b.Fail()
		}

		// change sk
		vData, vErr := VerifyEncSignedData(cKeyPair.PrivateKey, aKeyPair.PublicKey, signedData)
		if vErr == nil || vData != "" {
			b.Fail()
		}

		// change pk
		vData, vErr = VerifyEncSignedData(bKeyPair.PrivateKey, cKeyPair.PublicKey, signedData)
		if vErr == nil ||  vData != ""{
			b.Fail()
		}

		// change hash
		changedSignedData := *signedData
		changedSignedData.Hash = changedSignedData.Hash[4:] + "0000"

		vData, vErr = VerifyEncSignedData(bKeyPair.PrivateKey, aKeyPair.PublicKey, &changedSignedData)
		if vErr == nil || vData != "" {
			b.Fail()
		}

		// change sig
		changedSignedData = *signedData
		changedSignedData.Sig = changedSignedData.Sig[4:] + "0000"

		vData, vErr = VerifyEncSignedData(bKeyPair.PrivateKey, aKeyPair.PublicKey, &changedSignedData)
		if vErr == nil || vData != "" {
			b.Fail()
		}

		// change data
		changedSignedData = *signedData
		changedSignedData.DataEnc = changedSignedData.DataEnc[4:] + "0000"

		vData, vErr = VerifyEncSignedData(bKeyPair.PrivateKey, aKeyPair.PublicKey, &changedSignedData)
		if vErr == nil || vData != "" {
			b.Fail()
		}

	}
	
}

