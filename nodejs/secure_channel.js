const crypto = require('crypto')
const eckey = require('ecdsa-secp256r1')
const bigint = require('bigi')
const ecurve = require('ecurve')

const ec256r1 = ecurve.getCurveByName('secp256r1')
const ecdh = crypto.createECDH('prime256v1') // secp256r1 = prime256v1

function generateECKeyPair() {
    ecdh.generateKeys()

    skBArr = ecdh.getPrivateKey() // 32 bytes
    pkBArr = ecdh.getPublicKey() // 65 bytes

    for (let i = skBArr.length; i < 32; i++) {
        skBArr = Buffer.concat([Buffer.from('00', 'hex'), skBArr])
    }

    skHex = skBArr.toString('hex')
    pkHex = pkBArr.slice(1).toString('hex')

    // curve prime256v1
    const ecKeyPair = {
        PublicKey: pkHex, // format x || y, 64 bytes in hex string
        PrivateKey: skHex // 32 bytes in hex string
    }

    return ecKeyPair
}

function calSignedData(selfSkHexStr, data) {

    let dataByteArr = Buffer.from(data)
    let hash = crypto.createHash('sha256').update(dataByteArr).digest().toString('hex')

    let sign = crypto.createSign('sha256');
    sign.update(dataByteArr) // byte array
    sign.end()

    let skPem = recoverPemPrivateKey(selfSkHexStr)
    let sig = sign.sign({ key: skPem, dsaEncoding: 'ieee-p1363' }).toString('hex')

    const signedData = {
        Data: data,
        Hash: hash, // hash of data, length 32 bytes in hex string
        Sig: sig // ieee-p1363 format, a.k.a r||s, length 64 bytes in hex string
    }
    
    return signedData
}

function verifySignedData(fromPkHexStr, signedData) {

    let dataByteArr = Buffer.from(signedData.Data)
    let hashCal = crypto.createHash('sha256').update(dataByteArr).digest().toString('hex')

	// verify hash
	if (hashCal != signedData.Hash) {
        return false
	}

    // verify signature

    if(signedData.Sig.length != 128) {
        throw new TypeError("invalid signature, should in ieee-p1363 format, a.k.a. r || s with length 64 bytes")
	}

    let sigByteArr = Buffer.from(signedData.Sig, 'hex')
    let pkPem = recoverPemPublicKey(fromPkHexStr)

    let  verify = crypto.createVerify('sha256');
    verify.update(dataByteArr);
    verify.end();

    let result = verify.verify( { key: pkPem, dsaEncoding: 'ieee-p1363'}, sigByteArr)

    return result
}

function calEncSignedData(selfSkHexStr, toPkHexStr, data) {

    let signedData = calSignedData(selfSkHexStr, data)

    let r = crypto.randomBytes(32);
    let iv = crypto.randomBytes(16);
    let ivHexStr = iv.toString('hex')

    let rBigI = bigint.fromBuffer(r)
    rBigI = rBigI.mod(ec256r1.n)
    let RPoint = ec256r1.G.multiply(rBigI)
    let RxHexStr = RPoint.affineX.toBuffer(32).toString('hex')
    let RyHexStr = RPoint.affineY.toBuffer(32).toString('hex')

    let pkXBigI = bigint.fromBuffer(Buffer.from(toPkHexStr.slice(0, 64), 'hex'))
    let pkYBigI = bigint.fromBuffer(Buffer.from(toPkHexStr.slice(64), 'hex'))

    let PKPoint = ecurve.Point.fromAffine(ec256r1, pkXBigI, pkYBigI)
    let RPKPoint = PKPoint.multiply(rBigI)

    // AES key: hash(rPKx), (rPKx, rPKy) = r * pk = sk * R

    let keyAes = crypto.createHash('sha256').update(RPKPoint.affineX.toBuffer(32)).digest()

	// AES CTR encrypt

    let encrypt = crypto.createCipheriv('aes-256-ctr', keyAes, iv);
    let ciphertext = encrypt.update(Buffer.from(data));
    let ciphertextHexStr = Buffer.concat([ciphertext, encrypt.final()]).toString('hex')

    const encSignedData = {
        DataEnc: ivHexStr + RxHexStr + RyHexStr + ciphertextHexStr, 
        Hash: signedData.Hash, // hash of data, length 32 bytes in hex string
        Sig: signedData.Sig // ieee-p1363 format, a.k.a r||s, length 64 bytes in hex string
    }
    
    return encSignedData
}

function verifyEncSignedData(selfSkHexStr, fromPkHexStr, encSignedData) {

    let ivHexStr = encSignedData.DataEnc.slice(0,32)
    let RxHexStr = encSignedData.DataEnc.slice(32,96)
    let RyHexStr = encSignedData.DataEnc.slice(96,160)
    let ciphertextHexStr = encSignedData.DataEnc.slice(160)

    let iv = Buffer.from(ivHexStr, 'hex')

    let RxBigI = bigint.fromBuffer(Buffer.from(RxHexStr, 'hex'))
    let RyBigI = bigint.fromBuffer(Buffer.from(RyHexStr, 'hex'))
    let skBigI = bigint.fromBuffer(Buffer.from(selfSkHexStr, 'hex'))

    let RPoint = ecurve.Point.fromAffine(ec256r1, RxBigI, RyBigI)
    let RPKPoint = RPoint.multiply(skBigI)

    // AES key: hash(rPKx), (rPKx, rPKy) = r * pk = sk * R

    let keyAes = crypto.createHash('sha256').update(RPKPoint.affineX.toBuffer(32)).digest()

	// AES CTR decrypt
	// note: decrypt always success, however is not the real plaintext with wrong selfSkHexStr

    let decrypt = crypto.createDecipheriv('aes-256-ctr', keyAes, iv);
    let plaintextBytes = decrypt.update(Buffer.from(ciphertextHexStr, 'hex'));
    plaintextBytes = Buffer.concat([plaintextBytes, decrypt.final()]);

    let plaintext = plaintextBytes.toString()
    
	// verify hash and signature

	let signedData = {
        Data: plaintext,
        Hash: encSignedData.Hash,
        Sig: encSignedData.Sig
    }

	return verifySignedData(fromPkHexStr, signedData)
}

function recoverPemPrivateKey(skHexStr) {
    if (skHexStr.length != 64 || skHexStr.length %2 != 0){
        throw new TypeError('invalid EC private key, wrong length')
    }

    let skByteArr = Buffer.from(skHexStr, 'hex');
    let skBigI = bigint.fromBuffer(skByteArr)
    var pkPoint = ec256r1.G.multiply(skBigI)

    let sk = new eckey({
        d: skByteArr,
        x: pkPoint.affineX.toBuffer(32),
        y: pkPoint.affineY.toBuffer(32)
    })

    return sk.toPEM()
}

function recoverPemPublicKey(pkHexStr) {
    if (pkHexStr.length != 128 || pkHexStr.length %2 != 0){
        throw new TypeError('invalid EC point public key, wrong length')
    }

    let pkByteArr = Buffer.from(pkHexStr, 'hex');

    let pk = new eckey({
        x: pkByteArr.slice(0, 32),
        y: pkByteArr.slice(32)
    })

    return pk.toPEM()
}

module.exports = {
    generateECKeyPair: generateECKeyPair,
    calSignedData: calSignedData,
    verifySignedData: verifySignedData,
    calEncSignedData: calEncSignedData,
    verifyEncSignedData: verifyEncSignedData
};