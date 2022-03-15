const sc = require('.')

let data = "Test data 1	Test data 2	Test data 3	Test data 4	Test data 5	Test data 6	Test data 7	Test data 8	Test data 9	Test data 10	Test data 11	Test data 12	Test data 13	Test data 14	Test data 15	Test data 16	Test data 17	Test data 18	Test data 19	Test data 20	Test data 21	Test data 22	Test data 23	Test data 24	Test data 25	Test data 26"

let benchCount = 10


console.log('test generateECKeyPair')

for(let i = 0; i < benchCount; i++) {

    let keypair = sc.generateECKeyPair()

    let result = (keypair.PrivateKey.length + keypair.PublicKey.length) == 192

    console.log(result)
    if (!result) {
        console.log(keypair)
    }

}


console.log('test calSignedData and verifySignedData')

for(let i = 0; i < benchCount; i++) {

    let keypair = sc.generateECKeyPair()

    let signedData = sc.calSignedData(keypair.PrivateKey, data)

    let result  = sc.verifySignedData(keypair.PublicKey, signedData)
    
    console.log(result.Result)
    if (!result.Result) {
        console.log('invalid signature')
    }
}


console.log('test calEncSignedData and verifyEncSignedData')

for(let i = 0; i < benchCount; i++) {

    let akeypair = sc.generateECKeyPair()
    let bkeypair = sc.generateECKeyPair()

    let signedData = sc.calEncSignedData(akeypair.PrivateKey, bkeypair.PublicKey, data)

    let result  = sc.verifyEncSignedData(bkeypair.PrivateKey, akeypair.PublicKey, signedData)
    
    console.log(result.Result)
    if (!result.Result) {
        console.log('invalid signature')
    }
}






