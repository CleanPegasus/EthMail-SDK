const { ethers } = require("ethers");
const EthCrypto = require("eth-crypto");
const snarkjs = require("snarkjs");
const crypto = require("crypto");

const utils = require("./utils");

const ethMailAbi = require("../abi/EthMail.json").abi;

class Wallet {
  constructor(identity) {


    this.address = identity.address;
    this.privateKey = identity.privateKey;
    this.publicKey = identity.publicKey;
    // this.provider = new ethers.JsonRpcProvider(
    //   "https://polygon-mumbai.g.alchemy.com/v2/9QgbrEXeiMuUTHdrgY8Ac_EPr1bE4NXv"
    // );

    this.provider = new ethers.providers.JsonRpcProvider(
      "http://localhost:8545"
    );
    this.signer = new ethers.Wallet(this.privateKey, this.provider);

    this.ethMail = new ethers.Contract(
      "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
      ethMailAbi,
      this.signer
    );
  }

  async registerDomain(domain) {
    // const coder = ethers.AbiCoder.defaultAbiCoder()
    const encodedPublicKey = ethers.utils.defaultAbiCoder.encode(
      ["string"],
      [this.publicKey]
    );
    const tx = await this.ethMail
      .connect(this.signer)
      .registerDomain(domain, encodedPublicKey);
    await tx.wait();
    return tx;
  }

  async getDomain() {
    const domain = await this.ethMail["getDomainByOwner(address)"](this.address);
    return domain;
  }

  async createHandshake(receiverEthMail) {
    // const {receiverAddress, receiverPublicKey} = await this.ethMail.lookup(receiverEthMail);
    // const receiverPublicKey = await this.ethMail.lookup(receiverEthMail)[1];
    const receiverPublicKey = (await this.ethMail.lookup(receiverEthMail))[1];
    console.log("receiverPublicKey:", receiverPublicKey);
    const receiverAddress = (await this.ethMail.lookup(receiverEthMail))[0];
    console.log("receiverAddress:", receiverAddress);
    // const coder = ethers.AbiCoder.defaultAbiCoder()
    const receiverPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
      ["string"],
      receiverPublicKey
    )[0];

    console.log("receiverPublicKeyDecoded:", receiverPublicKeyDecoded);

    const senderRandomString = utils.createRandomNumber();
    const receiverRandomString = utils.createRandomNumber();

    const senderEthMail = await this.getDomain();

    const senderHandshakeRandomStrings = {
      receiver: receiverEthMail,
      senderRandomString: senderRandomString,
      receiverRandomString: receiverRandomString,
    };

    const encodedSenderHandshakeRandomStrings = JSON.stringify(
      senderHandshakeRandomStrings
    );

    const receiverHandshakeRandomStrings = {
      receiver: senderEthMail,
      senderRandomString: receiverRandomString,
      receiverRandomString: senderRandomString,
    };

    const encodedReceiverHandshakeRandomStrings = JSON.stringify(
      receiverHandshakeRandomStrings
    );

    // Encrypt the handshake with the public keys of the sender and the receiver
    const encryptedSenderRandomStrings = await utils.encryptData(
      this.publicKey,
      encodedSenderHandshakeRandomStrings
    );
    const encryptedReceiverRandomStrings = await utils.encryptData(
      receiverPublicKeyDecoded,
      encodedReceiverHandshakeRandomStrings
    );

    // Convert the encrypted messages to hex strings
    let encryptedSenderRandomHexs = ethers.utils.hexlify(
      ethers.utils.toUtf8Bytes(JSON.stringify(encryptedSenderRandomStrings))
    );
    let encryptedReceiverRandomHexes = ethers.utils.hexlify(
      ethers.utils.toUtf8Bytes(JSON.stringify(encryptedReceiverRandomStrings))
    );

    console.log("encryptedSenderRandomHexs:", encryptedSenderRandomHexs);

    const tx = await this.ethMail
      .createHandshake(
        senderEthMail,
        receiverAddress,
        encryptedSenderRandomHexs,
        encryptedReceiverRandomHexes
      );
    await tx.wait();

    return tx.hash;
  }

  async getUsersToAdd() {
    const usersToAdd = await this.ethMail.getAddedUsers(this.address);
    const usersToAddDecoded = usersToAdd.map(async (user) => {
      const receiverEncryptedRandomStringsDecoded = JSON.parse(
        ethers.utils.toUtf8String(user)
      );
      const decryptedReceiverKey = await utils.decryptMessage(
        receiverEncryptedRandomStringsDecoded,
        this.privateKey
      );
      const senderAddress = (
        await this.ethMail.lookup(JSON.parse(decryptedReceiverKey).receiver)
      )[0];
      console.log("senderAddress:", senderAddress);
      return {
        senderAddress: senderAddress,
        senderEthMail: JSON.parse(decryptedReceiverKey).receiver,
      };
    });
    return Promise.all(usersToAddDecoded);
  }

  async getAllUserHandshakes() {
    const [filter1, filter2] = [
      this.ethMail.filters.HandshakeCompleted(this.address, null),
      this.ethMail.filters.HandshakeCompleted(null, this.address),
    ];
    const [senderHandshakesEvents, receiverHandshakesEvent] = await Promise.all(
      [this.ethMail.queryFilter(filter1), this.ethMail.queryFilter(filter2)]
    );

    const senderAddresses = senderHandshakesEvents.map((event) => {
      return event.args[1];
    });
    const receiverAddresses = receiverHandshakesEvent.map((event) => {
      return event.args[0];
    });
    const allAddresses = [...senderAddresses, ...receiverAddresses];

    const allEthMail = await Promise.all(
      allAddresses.map(async (address) => {
        const domain = await this.ethMail.getDomainByOwner(address);
        return domain;
      })
    );

    return allEthMail;
  }

  async completeHandshake(index) {

    const receiverEncryptedRandomStrings = (
      await this.ethMail.getAddedUsers(this.address)
    )[index];

    console.log("receiverEncryptedRandomStrings:", await this.ethMail.getAddedUsers(this.address));

    const receiverEncryptedRandomStringsDecoded = JSON.parse(
      ethers.utils.toUtf8String(receiverEncryptedRandomStrings)
    );

    const decryptedReceiverKey = await utils.decryptMessage(
      receiverEncryptedRandomStringsDecoded,
      this.privateKey
    );

    const senderAddress = (
      await this.ethMail.lookup(JSON.parse(decryptedReceiverKey).receiver)
    )[0];
    console.log("senderAddress:", senderAddress);

    const domain = await this.getDomain();
    // Complete the handshake
    const tx = await this.ethMail
      .connect(this.signer)
      .completeHandshake(domain, senderAddress, receiverEncryptedRandomStrings);
    await tx.wait();

    return tx.hash;
  }

  async sendMessage(receiverEthMail, message) {
    const signedMessage = await this.createMessage(message);
    const receiverPublicKey = (await this.ethMail.lookup(receiverEthMail))[1];
    const receiverAddress = (await this.ethMail.lookup(receiverEthMail))[0];
    // const coder = ethers.AbiCoder.defaultAbiCoder()
    const receiverPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
      ["string"],
      receiverPublicKey
    )[0];
    const sharedKey = this.computeSharedKey(receiverPublicKeyDecoded);
    const encryptedMessage = JSON.stringify(
      utils.aesEncrypt(signedMessage, sharedKey)
    );

    const senderHandshakes = await this.ethMail.getHandshakes(
      this.address,
      receiverAddress
    );
    
    console.log("senderHandshakes:", ethers.utils.toUtf8String(senderHandshakes))

    const encryptedSenderRandomString = JSON.parse(
      ethers.utils.toUtf8String(senderHandshakes)
    );

    const decryptedSenderKey = JSON.parse(
      await utils.decryptMessage(encryptedSenderRandomString, this.privateKey)
    );

    const lastMessageHash = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(encryptedMessage + Date.now().toString())
    );
    const nonce = (await this.ethMail.getNonce(this.address)).toBigInt();
    const calldatas = await utils.createProof(
      decryptedSenderKey.senderRandomString,
      nonce
    );

    const tx = await this.ethMail
      .connect(this.signer)
      .sendMessage(
        encryptedMessage,
        lastMessageHash,
        calldatas[0],
        calldatas[1],
        calldatas[2],
        calldatas[3]
      );
    await tx.wait();
    console.log("Message sent");
  }

  // utils
  computeSharedKey(publicKey) {
    const dhke = crypto.createECDH("secp256k1");
    console.log("publicKey:", publicKey);
    dhke.setPrivateKey(this.privateKey, "hex");
    const sharedKey = dhke.computeSecret(publicKey, "hex");
    return sharedKey;
  }

  async createMessage(message) {
    const detailedMessage = {
      sender: this.address,
      message: message,
      timestamp: Date.now(),
    };
    const signature = await this.signer.signMessage(
      JSON.stringify(detailedMessage)
    );
    const signedMessage = {
      message: detailedMessage,
      signature: signature,
    };
    return JSON.stringify(signedMessage);
  }
}

module.exports = {
  Wallet,
};
