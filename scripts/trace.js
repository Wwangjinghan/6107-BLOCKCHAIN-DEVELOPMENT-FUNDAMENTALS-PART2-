import fs from "node:fs";
import { createPublicClient, createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import DemoArtifact from "../artifacts/contracts/Demo.sol/Demo.json"; // 确保路径正确

const RPC_URL = process.env.SEPOLIA_RPC_URL;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

async function main() {
    if (!RPC_URL || !PRIVATE_KEY) {
        throw new Error("请在 .env 文件中配置 SEPOLIA_RPC_URL 和 PRIVATE_KEY");
    }

    // 创建客户端
    const account = privateKeyToAccount(PRIVATE_KEY);
    const publicClient = createPublicClient({
        chain: sepolia,
        transport: http(RPC_URL),
    });
    const walletClient = createWalletClient({
        account,
        chain: sepolia,
        transport: http(RPC_URL),
    });

    // 1️⃣ 部署 Demo 合约
    console.log("Deploying Demo contract...");
    const deployTxHash = await walletClient.deployContract({
        abi: DemoArtifact.abi,
        bytecode: DemoArtifact.bytecode,
        args: [],
        gas: 1000000,
    });
    console.log("Deploy tx hash:", deployTxHash);

    const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployTxHash });
    const demoAddress = deployReceipt.contractAddress;
    console.log("Demo contract deployed at:", demoAddress);

    // 2️⃣ 调用 set() 生成交易
    console.log("Calling set(123)...");
    const txHash = await walletClient.writeContract({
        address: demoAddress,
        abi: DemoArtifact.abi,
        functionName: "set",
        args: [123],
        gas: 100000,
    });
    console.log("Transaction hash:", txHash);

    await publicClient.waitForTransactionReceipt({ hash: txHash });
    console.log("Transaction confirmed");

    // 3️⃣ 抓取 trace
    const traceData = await publicClient.send("debug_traceTransaction", [txHash, {}]);
    fs.writeFileSync("trace.json", JSON.stringify(traceData, null, 2));
    console.log("Trace saved to trace.json");
    console.log("structLogs length:", traceData.result.structLogs.length);

    // 4️⃣ 读取当前状态
    const value = await publicClient.readContract({
        address: demoAddress,
        abi: DemoArtifact.abi,
        functionName: "x",
        args: [],
    });
    console.log("Current value in contract:", value.toString());
}

main();
