
## secure_channel

------

A golang implementation toolkit, aim to secure the communication channel based on Hash(sha256), Digital Signature(ecdsa with curve secp256r1 or prime256v1) and Encryption(aes with CTR mode).

### Uasge

#### install

    go get github.com/anyswap/SecureToolkit/golang/secure_channel

#### create **signed** data, and verify

    package main

    import (
        sc "github.com/anyswap/SecureToolkit/golang/secure_channel"
    )
    
    func main() {
        
        senderKeyPair := sc.GenerateECKeyPair()

        data := "hello world"

        signedData, _ := sc.CalSignedData(senderKeyPair.PrivateKey, data)

        // if signedData has been changed or no from the right sender, the following verification will fail

        result, _ := sc.VerifySignedData(senderKeyPair.PublicKey, signedData)

    }

#### create **signed encrypted** data, and verify

    package main

    import (
        sc "github.com/anyswap/SecureToolkit/golang/secure_channel"
    )
    
    func main() {
        
        senderKeyPair := sc.GenerateECKeyPair()
        receiverKeyPair := sc.GenerateECKeyPair()

        data := "hello world"

        encSignedData, _ := sc.CalEncSignedData(senderKeyPair.PrivateKey, receiverKeyPair.PublicKey, data)

        // the encSignedData is encrypted, can not learn anything about the data
        // and if encSignedData has been changed or no from the right sender, the following verification will fail

        result, _ := sc.VerifyEncSignedData(receiverKeyPair.PrivateKey, senderKeyPair.PublicKey, encSignedData)

    }