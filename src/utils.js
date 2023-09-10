const { ethers } = require("ethers");
const EthCrypto = require("eth-crypto");
const crypto = require("crypto");
const circomlibjs = require("circomlibjs");
const snarkjs = require("snarkjs");

function createRandomNumber() {
  // Generate a random 32-byte hexadecimal number
  const randomBytes = ethers.utils.randomBytes(32);

  // Convert the random bytes to a BigNumber
  const randomNumber = ethers.BigNumber.from(randomBytes);

  return randomNumber.toString();
}

async function encryptData(publicKey, message) {
  const encryptedMessage = await EthCrypto.encryptWithPublicKey(
    publicKey, // publicKey
    message // message
  );

  return EthCrypto.cipher.stringify(encryptedMessage);
}

async function decryptMessage(encryptedMessage, privateKey) {
  const parsedMessage = EthCrypto.cipher.parse(encryptedMessage);
  const decryptedMessage = await EthCrypto.decryptWithPrivateKey(
    privateKey, // privateKey
    parsedMessage // encrypted-data
  );
  return decryptedMessage;
}

function aesEncrypt(message, sharedKey) {
  const iv = crypto.randomBytes(16); // Random initialization vector
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    sharedKey.slice(0, 32),
    iv
  ); // Use only the first 32 bytes as the key
  let encrypted = cipher.update(message, "utf8", "hex");
  encrypted += cipher.final("hex");

  return { iv, encrypted };
}

function aesDecrypt(encryptedMessage, sharedKey) {
  // Decrypt the message with the shared secret
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    sharedKey.slice(0, 32),
    Buffer.from(encryptedMessage.iv.data)
  );
  let decrypted = decipher.update(encryptedMessage.encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

async function createProof(randomString, nonce) {
  const randomStringBigInt = ethers.BigNumber.from(randomString).toBigInt();
  const poseidon = await circomlibjs.buildPoseidon();
  const hash = poseidon.F.toString(poseidon([randomStringBigInt]));
  const hash_with_nonce = poseidon.F.toString(
    poseidon([randomStringBigInt, nonce])
  );

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      preImage: randomStringBigInt,
      nonce: nonce,
      preImageHash: hash,
      hashedValue: hash_with_nonce,
    },
    "build/nonce_hasher_js/nonce_hasher.wasm",
    "circuit_0000.zkey"
  );
  // console.log('publicSignals:', publicSignals)
  const calldatas = await snarkjs.groth16.exportSolidityCallData(
    proof,
    publicSignals
  );
  const formattedCalldata = JSON.parse("[" + calldatas + "]");

  return formattedCalldata;
}

async function verifyMessage(signedMessage, senderAddress) {
  const { message, signature } = JSON.parse(signedMessage);
  const recoveredAddress = ethers.utils.verifyMessage(
    JSON.stringify(message),
    signature
  );

  return recoveredAddress === senderAddress;
}

async function poseidonHash(key) {
  const poseidon = await circomlibjs.buildPoseidon();
  const hash = poseidon.F.toString(poseidon([BigInt(key)]));
  return hash;
}

function createECDHIdentity() {
  const alice = crypto.createECDH("secp256k1");
  alice.generateKeys();

  // Get public and private keys in hex format
  const publicKey = alice.getPublicKey("hex");
  const privateKey = alice.getPrivateKey("hex");

  const address = EthCrypto.publicKey.toAddress(publicKey);

  // const signer = new ethers.Wallet(privateKey, ethers.provider);

  return {
    address: address,
    privateKey: privateKey,
    publicKey: publicKey,
    // signer: signer,
  };
}

module.exports = {
  createRandomNumber,
  encryptData,
  decryptMessage,
  aesEncrypt,
  aesDecrypt,
  createProof,
  verifyMessage,
  poseidonHash,
  createECDHIdentity,
};
