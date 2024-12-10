// scripts/deploy.js

const { ethers, upgrades } = require("hardhat");

async function main() {
  // Deploy the implementation contract
  const CoinbaseSmartWallet = await ethers.getContractFactory("CoinbaseSmartWallet");
  const implementation = await CoinbaseSmartWallet.deploy();
  await implementation.deployed();
  console.log("CoinbaseSmartWallet implementation deployed at:", implementation.address);

  // Owners array: Here we encode one Ethereum-based owner.
  // This should be bytes[], where each element is `abi.encode(address)`.
  // For simplicity, we'll just pick the deployer as the owner. In practice, you can choose another address.
  const [deployer] = await ethers.getSigners();
  const owners = [ethers.utils.defaultAbiCoder.encode(["address"], [deployer.address])];

  // Encode the initializer call
  const initData = implementation.interface.encodeFunctionData("initialize", [owners]);

  // Deploy the UUPS proxy using the ERC1967Proxy
  // The ERC1967Proxy constructor is (implementationAddress, initializerData)
  // You must have the ERC1967Proxy contract compiled. 
  //
  // If you do not have it compiled locally, you can import it from 
  // '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol' 
  // and create a dedicated factory, or use the OpenZeppelin Upgrades Plugin.
  //
  // Below is the manual deployment using ethers:
  
  const ERC1967Proxy = await ethers.getContractFactory("ERC1967Proxy");
  const proxy = await ERC1967Proxy.deploy(implementation.address, initData);
  await proxy.deployed();
  console.log("Proxy deployed at:", proxy.address);

  // Create a contract instance pointing to the proxy, using the implementation ABI
  const wallet = CoinbaseSmartWallet.attach(proxy.address);

  // Verify if initialized correctly:
  const entryPoint = await wallet.entryPoint();
  console.log("Entry Point:", entryPoint);

  console.log("Deployment complete. Your CoinbaseSmartWallet proxy is ready at:", wallet.address);
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
