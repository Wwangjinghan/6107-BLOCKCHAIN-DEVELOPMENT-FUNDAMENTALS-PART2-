const { createPublicClient, createWalletClient, http } = require("viem");
const { privateKeyToAccount } = require("viem/accounts");
const { hardhat } = require("viem/chains");
const DemoArtifact = require("../artifacts/contracts/Demo.sol/Demo.json");

async function main() {
  const publicClient = createPublicClient({
    chain: hardhat,
    transport: http("http://127.0.0.1:8545"),
  });

  const account = privateKeyToAccount(
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  );

  const walletClient = createWalletClient({
    account,
    chain: hardhat,
    transport: http("http://127.0.0.1:8545"),
  });

  const hash = await walletClient.deployContract({
    abi: DemoArtifact.abi,
    bytecode: DemoArtifact.bytecode,
    args: [],
  });

  console.log("deploy tx hash:", hash);

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  console.log("contract address:", receipt.contractAddress);

  const callHash = await walletClient.writeContract({
    address: receipt.contractAddress,
    abi: DemoArtifact.abi,
    functionName: "set",
    args: [42],
  });

  console.log("set tx hash:", callHash);
}

main();
