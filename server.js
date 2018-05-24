
/*
Verify the signature as follows:

Ensure that the certificates contain the correct custom OIDs:
1.2.840.113635.100.6.29 for the leaf certificate
1.2.840.113635.100.6.2.14 for the intermediate CA
The value for these marker OIDs doesn’t matter, only their presence.

Ensure that the root CA is the Apple Root CA - G3. This certificate is available from http://apple.com/certificateauthority.

Ensure that there is a valid X.509 chain of trust from the signature to the root CA. Specifically, ensure that the signature was created using the private key corresponding to the leaf certificate, that the leaf certificate is signed by the intermediate CA, and that the intermediate CA is signed by the Apple Root CA - G3.

Ensure that the signature is a valid ECDSA signature (ecdsa-with-SHA256 1.2.840.10045.4.3.2) of the concatenated values of the ephemeralPublicKey, data,transactionId, and applicationData keys.

Inspect the CMS signing time of the signature, as defined by section 11.3 of RFC 5652. If the time signature and the transaction time differ by more than a few minutes, it's possible that the token is a replay attack.

Use the value of the publicKeyHash key to determine which merchant public key was used by Apple, and then retrieve the corresponding merchant public key certificate and private key.

Using the merchant private key and the ephemeral public key, generate the shared secret using Elliptic Curve Diffie-Hellman (id-ecDH 1.3.132.1.12).

Using the merchant identifier field (OID 1.2.840.113635.100.6.32) of the public key certificate and the shared secret, derive the symmetric key using the key derivation function described in NIST SP 800-56A, section 5.8.1, with the following input values:*/

var request = require('request');
var express = require('express');
var x509 = require('x509');
var fs = require('fs');
var crypto = require('crypto');

var CERT_PATH = './certificate.pem';
var PRIVATE_KEY_PATH = './private_key.pem';
var TOKEN_PATH = './token.json'

var cert = fs.readFileSync(CERT_PATH, 'utf8');
var forge = require('node-forge');

var app = express();

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});

app.get('/merchant-session/new', function(req, res) {
  var merchantIdentifier = extractMerchantID(cert);
  var uri = req.query.validationURL || 'https://apple-pay-gateway-cert.apple.com/paymentservices/startSession';

  var options = {
    uri: uri,
    json: {
      merchantIdentifier: merchantIdentifier,
      domainName: process.env.APPLE_PAY_DOMAIN,
      displayName: process.env.APPLE_PAY_DISPLAY_NAME
    },

    agentOptions: {
      cert: cert,
      key: cert
    }
  };

  request.post(options, function(error, response, body) {
    if (body) {
      // Apple returns a payload with `displayName`, but passing this
      // to `completeMerchantValidation` causes it to error.
      delete body.displayName;
    }

    res.send(body);
    console.log("POST");
  });
});

app.get('/decrypt', function(req, res) {
  var pk = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
  var cut = "-----BEGIN EC PRIVATE KEY-----";
  var cutEnd = "-----END EC PRIVATE KEY-----";
  var start = pk.indexOf(cut)+cut.length+1;
  var end = pk.indexOf(cutEnd)-start-1;
  var key = pk.substr(start, end);

  var tokenString = fs.readFileSync(TOKEN_PATH, 'utf8');

  var token = JSON.parse(tokenString);
  var ephemeralPublicKey = token['header']['ephemeralPublicKey']
  
  //Generating shared Secret
  let sharedSecret = generateSharedSecret(key, ephemeralPublicKey);
  
  // Generating symmetricKey Key
  var merchantId = extractMerchantID(cert);
  let symmetricKey = generateSymmetricKey(merchantId, sharedSecret);
  var ciphertext = token['data'];

  // Decrypt Cipher text
  let decrypted = decryptCiphertext(symmetricKey, ciphertext);

  //TODO: Determine if -14 is correct, my decrypted string had extra junk at the end.  Not sure if this will apply to all tokens.
  var decryptedClean = decrypted.slice(0, -14);
  console.log(decryptedClean);
});

var server = app.listen(process.env.PORT || 3000, function() {
  console.log('Apple Pay server running on ' + server.address().port);
  console.log('GET /merchant-session/new to retrieve a merchant session');
  console.log('GET /decrypt to check decryption');
});

function extractMerchantID(cert) {
  try {
    var info = x509.parseCert(cert);

    return info.extensions['1.2.840.113635.100.6.32'].substr(2);
  } catch (e) {
    console.error("Unable to extract merchant ID from certificate " + CERT_PATH);
  }
}

function generateSharedSecret(merchantPrivateKey, ephemeralPublicKey) {
  let om, ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(((new Buffer(merchantPrivateKey, 'base64')).toString('hex')).substring(14, 64 + 14),'hex'); // 14: Key start, 64: Key length
  
  try {
    om = ecdh.computeSecret(((new Buffer(ephemeralPublicKey, 'base64')).toString('hex')).substring(52, 130 + 52),'hex','hex'); // 52: Key start, 130: Key length
  } catch(e) {
    console.log(e);
    return e;
  }
	
  return om;
}

function generateSymmetricKey(merchantId, sharedSecret) {
    const KDF_ALGORITHM = String.fromCharCode(0x0D) + 'id-aes256-GCM';
    KDF_PARTY_V = (new Buffer(merchantId, 'hex')).toString('binary');
    KDF_INFO = KDF_ALGORITHM + 'Apple' + KDF_PARTY_V;
    
    let hash = crypto.createHash('sha256');
    hash.update(new Buffer('000000', 'hex'));
    hash.update(new Buffer('01', 'hex'));
    hash.update(new Buffer(sharedSecret, 'hex'));
    
    // From nodejs V6 use --> hash.update(KDF_INFO, 'binary');
    hash.update(KDF_INFO, 'binary');

    return hash.digest('hex');
}

function decryptCiphertext(symmetricKey, ciphertext) {
    const SYMMETRIC_KEY = forge.util.createBuffer((new Buffer(symmetricKey, 'hex')).toString('binary'));
    const IV = forge.util.createBuffer((new Buffer([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])).toString('binary'));
    const CIPHERTEXT = forge.util.createBuffer(forge.util.decode64(ciphertext));

    let decipher = forge.cipher.createDecipher('AES-GCM', SYMMETRIC_KEY);
    var tag = forge.util.decode64("");

    decipher.start({
      iv: IV,
      tagLength: 0,
      tag: tag
    });
    
    decipher.update(CIPHERTEXT);
    decipher.finish();
    return (new Buffer (decipher.output.toHex(), 'hex').toString('utf-8'));
}


