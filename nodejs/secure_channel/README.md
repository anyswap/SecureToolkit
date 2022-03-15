
## secure_channel

------

A Node.js implementation toolkit, aim to secure the communication channel based on Hash(sha256), Digital Signature(ecdsa with curve secp256r1 or prime256v1) and Encryption(aes with CTR mode).

### Uasge

#### install

    npm i secure_channel

#### create **signed** data, and verify

    var sc = require('secure_channel')

    var senderKeyPair = sc.generateECKeyPair()

    var data = "hello world"

    var signedData = sc.calSignedData(senderKeyPair.PrivateKey, data)

    // if signedData has been changed or no from the right sender, the following verification will fail

    var result = sc.verifySignedData(senderKeyPair.PublicKey, signedData)


#### create **signed encrypted** data, and verify

    var sc = require('secure_channel')

    var senderKeyPair = sc.generateECKeyPair()
    var receiverKeyPair = sc.generateECKeyPair()

    var data = "hello world"

    var encSignedData = sc.calEncSignedData(senderKeyPair.PrivateKey, receiverKeyPair.PublicKey, data)

    // the encSignedData is encrypted, can not learn anything about the data
    // and if encSignedData has been changed or no from the right sender, the following verification will fail

    var result = sc.verifyEncSignedData(receiverKeyPair.PrivateKey, senderKeyPair.PublicKey, encSignedData)


