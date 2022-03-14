const sc = require('./secure_channel')
const fs = require('fs')


function outputForNodejs(prefix) {

    // create output content

    let contentOutput = ""

    contentOutput += "# output by nodejs, verify by golang\n"
    contentOutput += "# verify need bkeypair.PrivateKey, akeypair.PublicKey, signedData (DataEnc, Hash, Sig)\n"

    for(let i = 0; i < benchCount; i++) {

        let akeypair = sc.generateECKeyPair()
        let bkeypair = sc.generateECKeyPair()

        contentOutput += bkeypair.PrivateKey + "\n"
        contentOutput += akeypair.PublicKey + "\n"

        let signedData = sc.calEncSignedData(akeypair.PrivateKey, bkeypair.PublicKey, data)

        contentOutput += signedData.DataEnc + "\n"
        contentOutput += signedData.Hash + "\n"
        contentOutput += signedData.Sig + "\n"
    }

    // write to file

    try {
        fs.writeFileSync(`./${prefix}cross_verify_output_nodejs.txt`, contentOutput)
    } catch (err) {
        console.error(`failed to write, ${err}`)
    }

	console.log("output finished")
}


function verifyNodejsOutput(prefix) {

    let inputContent = ""

    try {
        inputContent = fs.readFileSync(`${prefix}cross_verify_output_go.txt`, 'utf8')
    } catch (err) {
        console.error(`failed to read, ${err}`)
        return 
    }

    // loop input content
    let lines = inputContent.split("\n").slice(2)
    let count = parseInt(lines.length / 5)

    for(let i = 0; i < count; i++){

        let start = i * 5
        let bPrivateKey = lines[start++]
		let aPublicKey = lines[start++]
		let dataEnc = lines[start++]
		let hash = lines[start++]
		let sig = lines[start]

        let encSignedData = {
            DataEnc: dataEnc, 
            Hash: hash,
            Sig: sig
        }

        let result = sc.verifyEncSignedData(bPrivateKey, aPublicKey, encSignedData)
        
        console.log("------")
		console.log(result.Data)
		if (!result.Result) {
			console.log("failed to verify!")
		}
    }

}



let data = "Test data 1	Test data 2	Test data 3	Test data 4	Test data 5	Test data 6	Test data 7	Test data 8	Test data 9	Test data 10	Test data 11	Test data 12	Test data 13	Test data 14	Test data 15	Test data 16	Test data 17	Test data 18	Test data 19	Test data 20	Test data 21	Test data 22	Test data 23	Test data 24	Test data 25	Test data 26"

let benchCount = 10





let prefixOutput = "03.14_"
	
outputForNodejs(prefixOutput)

let prefixNodejsOutput = "../golang/secure_channel_cross_verify/03.14_"

verifyNodejsOutput(prefixNodejsOutput)


