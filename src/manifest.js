const { encode, decode } = require('ripple-binary-codec')
const { decodeNodePublic, encodeNodePublic } = require('ripple-address-codec')
const { verify } = require('ripple-keypairs')

/**
 * Parse a manifest
 *
 * @param binary hex-string of an encoded manifest
 */
function parseManifest(manifest) {
    let parsed;
    try {
        parsed = decode(manifest)
    }
    catch(e) {
        console.log(`Error Decoding Manifest: ${e}`)
        return;
    }

    const result = {
        Sequence: parsed['Sequence'],
        Signature: parsed['Signature'],
        MasterSignature: parsed['MasterSignature']
    }

    if(parsed['Domain'])
        result['Domain'] = Buffer.from(parsed['Domain'], 'hex').toString()

    if(parsed['PublicKey'])
        result['PublicKey'] = encodeNodePublic(Buffer.from(parsed['PublicKey'], 'hex'))

    if(parsed['SigningPubKey'])
        result['SigningPubKey'] = encodeNodePublic(Buffer.from(parsed['SigningPubKey'], 'hex'))

    return result
}

/**
 * Verify a parsed manifest
 * 
 * @param manifest a manifest object
 */
function verifyManifestSignature(manifest) {
    const s = manifest['MasterSignature'] ? manifest['MasterSignature'] : manifest['Signature']
    const signature = Buffer.from(s, 'hex').toString('hex')

    const signed = Object.assign({}, manifest)
    delete signed['MasterSignature']
    delete signed['Signature']

    if(signed['Domain'])
        signed['Domain'] = Buffer.from(signed['Domain']).toString('hex')

    if(signed['PublicKey'])
        signed['PublicKey'] = decodeNodePublic(signed['PublicKey']).toString('hex')

    if(signed['SigningPubKey'])
        signed['SigningPubKey'] = decodeNodePublic(signed['SigningPubKey']).toString('hex')
        
    const signed_bytes = encode(signed)

    const manifestPrefix = Buffer.from("MAN\0")
    const data = Buffer.concat([manifestPrefix, Buffer.from(signed_bytes, 'hex')]).toString('hex')
    const key = Buffer.from(signed['PublicKey'], 'hex').toString('hex')

    return verify(data, signature, key)
}

module.exports = {
    parseManifest,
    verifyManifestSignature
}