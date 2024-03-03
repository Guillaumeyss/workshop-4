import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // implement this function using the crypto package to generate a public and private RSA key pair.
  //      the public key should be used for encryption and the private key for decryption. Make sure the
  //      keys are extractable.

 

  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true, // Make the key pair extractable
    ['encrypt', 'decrypt'] // Key usages for the public and private keys
  );

  return keyPair ;
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  // Export the public key as a base64 string using the Web Crypto API
  const exportedKey = await webcrypto.subtle.exportKey('spki', key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  const exportedKeyBase64 = Buffer.from(exportedKeyBuffer).toString('base64');

  // Return the base64 string version of the public key
  return exportedKeyBase64;
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // Export the private key as a base64 string using the Web Crypto API
  if (key === null) {
    return null;
  }

  const exportedKey = await webcrypto.subtle.exportKey('pkcs8', key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  const exportedKeyBase64 = Buffer.from(exportedKeyBuffer).toString('base64');

  // Return the base64 string version of the private key
  return exportedKeyBase64;
}

// Import a base64 string public key to its native format
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  // Import the public key from a base64 string using the Web Crypto API
  const base64Key = Buffer.from(strKey, 'base64');
  const keyData = new Uint8Array(base64Key);
  const importedKey = await webcrypto.subtle.importKey(
    'spki',
    keyData,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['encrypt']
  );

  // Return the imported public key as a CryptoKey object
  return importedKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // Import the private key from a base64 string using the Web Crypto API
  const base64Key = Buffer.from(strKey, 'base64');
  const keyData = new Uint8Array(base64Key);
  const importedKey = await webcrypto.subtle.importKey(
    'pkcs8',
    keyData,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true,
    ['decrypt']
  );

  return importedKey;
}

export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  

  const publicKey = await importPubKey(strPublicKey);
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    base64ToArrayBuffer(b64Data)
  );

  return arrayBufferToBase64(encryptedData);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {

  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    base64ToArrayBuffer(data)
  );

  // remove this
  return arrayBufferToBase64(decryptedData);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  const key = await crypto.subtle.generateKey(
    {
      name: "AES-CBC",
      length: 256, // 256-bit key
    },
    true, // extractable
    ["encrypt", "decrypt"] // key usages
  );

  return key;
}

export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // Export the symmetric key as a base64 string using the Web Crypto API
  const exportedKey = await webcrypto.subtle.exportKey('raw', key);
  const exportedKeyArrayBuffer = new Uint8Array(exportedKey);
  const exportedKeyBase64 = Buffer.from(exportedKeyArrayBuffer).toString('base64');

  // Return the base64 string version of the symmetric key
  return exportedKeyBase64;
}

export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // Import the symmetric key from a base64 string using the Web Crypto API
  const base64Key = Buffer.from(strKey, 'base64');
  const keyData = new Uint8Array(base64Key);
  const importedKey = await webcrypto.subtle.importKey(
    'raw',
    keyData,
    {
      name: 'AES-CBC',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );

  // Return the imported symmetric key as a CryptoKey object
  return importedKey;
}

export async function symEncrypt(
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: encode the data to a uin8array with TextEncoder
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
const iv = webcrypto.getRandomValues(new Uint8Array(16));
const encrypted = await webcrypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv: iv,
    },
    key,
    new TextEncoder().encode(data)
);
return arrayBufferToBase64(iv) + ':' + arrayBufferToBase64(encrypted);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
const key = await importSymKey(strKey);
const parts = encryptedData.split(':');
const iv = base64ToArrayBuffer(parts[0]);
const encrypted = base64ToArrayBuffer(parts[1]);

const decrypted = await webcrypto.subtle.decrypt(
    {
      name: 'AES-CBC',
      iv: iv,
    },
    key,
    encrypted
);
return new TextDecoder().decode(decrypted);
}