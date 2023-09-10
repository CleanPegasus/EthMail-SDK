const { ethers } = require("ethers");
const { Wallet } = require("../src/index");
const { createECDHIdentity } = require("../src/utils");

async function main() {

  const provider = new ethers.providers.JsonRpcProvider("http://localhost:8545");

  const deployer = new ethers.Wallet(
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    provider
  );
  const identity1 = createECDHIdentity();
  const identity2 = createECDHIdentity();
  const wallet1 = new Wallet(identity1);
  const wallet2 = new Wallet(identity2);

  await deployer.sendTransaction({
    to: wallet1.address,
    value: ethers.utils.parseEther("100"),
  });
  await deployer.sendTransaction({
    to: wallet2.address,
    value: ethers.utils.parseEther("100"),
  });

  await wallet1.registerDomain("wallet1.ethMail");
  await wallet2.registerDomain("wallet2.ethMail");

  const domain = await wallet1.getDomain();
  console.log("domain:", domain);

  await wallet1.createHandshake("wallet2.ethMail");

  const usersToAdd = await wallet2.getUsersToAdd();
  console.log("usersToAdd:", usersToAdd); // needs to be decoded

  await wallet2.completeHandshake(0);

  await wallet1.sendMessage("wallet2.ethMail", "Hello World!");

  
}

main();
