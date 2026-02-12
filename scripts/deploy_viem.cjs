// 加载环境变量
require('dotenv').config();

const { createPublicClient, createWalletClient, http } = require("viem");
const { privateKeyToAccount } = require("viem/accounts");
const { sepolia } = require("viem/chains");
const DemoArtifact = require("../artifacts/contracts/Demo.sol/Demo.json");

async function main() {
    const RPC_URL = process.env.SEPOLIA_RPC_URL;
    const PRIVATE_KEY = process.env.PRIVATE_KEY;

    if (!RPC_URL || !PRIVATE_KEY) {
        throw new Error("请在 .env 文件中配置 SEPOLIA_RPC_URL 和 PRIVATE_KEY");
    }

    // 创建客户端连接 Sepolia
    const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(RPC_URL),
    });

    const account = privateKeyToAccount(PRIVATE_KEY);

    const walletClient = createWalletClient({
        account,
        chain: sepolia,
        transport: http(RPC_URL),
    });

    console.log("Deploying Demo contract...");

    // 部署合约
    const deployTxHash = await walletClient.deployContract({
        abi: DemoArtifact.abi,
        bytecode: DemoArtifact.bytecode,
        args: [],
        // 可选：手动设置 gas
        gas: 1000000,
    });

    console.log("Deploy tx hash:", deployTxHash);

    // 等待部署交易被打包
    const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployTxHash });
    console.log("Contract deployed at:", deployReceipt.contractAddress);

    // 调用 set(42)
    console.log("Calling set(42)...");
    const setTxHash = await walletClient.writeContract({
        address: deployReceipt.contractAddress,
        abi: DemoArtifact.abi,
        functionName: "set",
        args: [42],
        gas: 100000, // 可选，根据合约大小调整
    });

    console.log("set tx hash:", setTxHash);

    // 等待 set 交易被矿工打包
    await publicClient.waitForTransactionReceipt({ hash: setTxHash });
    console.log("set(42) transaction confirmed");

    // 读取 x()
    console.log("Reading value from contract...");
    const value = await publicClient.readContract({
        address: deployReceipt.contractAddress,
        abi: DemoArtifact.abi,
        functionName: "x",
        args: [],
    });

    console.log("Current value in contract:", value.toString());
}

main();
