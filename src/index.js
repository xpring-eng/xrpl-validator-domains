const { parseManifest, verifyManifestSignature } = require('./manifest.js')
const { fetchToml } = require('./network.js')
const { decodeNodePublic } = require('ripple-address-codec');
const { verify } = require('ripple-keypairs')

async function verifyValidatorDomain(manifest) {
    let parsedManifest
    try {
        parsedManifest = parseManifest(manifest)
    }
    catch(error) {
        return {
            status: "error",
            message: `Cannot Parse Manifest: ${error}`,
        }
    }

    const domain = parsedManifest['Domain']
    const publicKey = parsedManifest['PublicKey']
    const decodedPubKey = decodeNodePublic(publicKey).toString('hex')

    if(!verifyManifestSignature(parsedManifest))
        return {
            status: "error",
            message: "Cannot verify manifest signature",
            manifest: parsedManifest
        }

    if(domain === undefined)
        return {
            status: "error",
            message: "Manifest does not contain a domain",
            manifest: parsedManifest
        }

    const validatorInfo = await fetchToml(domain)
    if(!validatorInfo.VALIDATORS)
        return {
            status: "error",
            message: ".toml file does not contain VALIDATORS",
            manifest: parsedManifest
        }


    const message = "[domain-attestation-blob:" + domain + ":" + publicKey + "]";
    const message_bytes = Buffer.from(message).toString('hex')

    const validators = validatorInfo.VALIDATORS.filter(validator => validator.public_key === publicKey)
    if(validators && validators.length === 0)
        return {
            status: "error",
            message: ".toml file does not have matching public key",
            manifest: parsedManifest
        }

    for (const validator of validators) {
        const attestation = Buffer.from(validator.attestation, 'hex').toString('hex')
        
        if(!verify(message_bytes, attestation, decodedPubKey)) {
            return {
                status: "error",
                message: `Invalid attestation, cannot verify ${domain}`,
                manifest: parsedManifest
            }
        }
    }

    return {
        status: "success",
        message: `${domain} has been verified`,
        manifest: parsedManifest
    }
}

module.exports = {
    verifyValidatorDomain,
    verifyManifestSignature
}