const sechannel = require('.')

let data = "Test data 1	Test data 2	Test data 3	Test data 4	Test data 5	Test data 6	Test data 7	Test data 8	Test data 9	Test data 10	Test data 11	Test data 12	Test data 13	Test data 14	Test data 15	Test data 16	Test data 17	Test data 18	Test data 19	Test data 20	Test data 21	Test data 22	Test data 23	Test data 24	Test data 25	Test data 26"

let benchCount = 10


// console.log('test generateECKeyPair')

// for(let i = 0; i < benchCount; i++) {

//     let keypair = sechannel.generateECKeyPair()

//     let result = (keypair.PrivateKey.length + keypair.PublicKey.length) == 192

//     console.log(result)
//     if (!result.result) {
//         console.log(keypair)
//     }

// }


// console.log('test calSignedData and verifySignedData')

// for(let i = 0; i < benchCount; i++) {

//     let keypair = sechannel.generateECKeyPair()

//     let signedData = sechannel.calSignedData(keypair.PrivateKey, data)

//     let result  = sechannel.verifySignedData(keypair.PublicKey, signedData)
    
//     console.log(result)
//     if (!result.Result) {
//         console.log('invalid signature')
//     }
// }


console.log('test calEncSignedData and verifyEncSignedData')

for(let i = 0; i < benchCount; i++) {

    let akeypair = sechannel.generateECKeyPair()
    let bkeypair = sechannel.generateECKeyPair()

    let signedData = sechannel.calEncSignedData(akeypair.PrivateKey, bkeypair.PublicKey, data)

    let result  = sechannel.verifyEncSignedData(bkeypair.PrivateKey, akeypair.PublicKey, signedData)
    
    console.log(result)
    if (!result.Result) {
        console.log('invalid signature')
    }
}






