import { createPublicClient, http } from "viem";
import { mainnet } from "viem/chains";

const client = createPublicClient({
    chain: mainnet,         // fork 主网
    transport: http("http://127.0.0.1:8545"),  // 本地节点
});

async function main() {
    const block = await client.getBlockNumber();
    console.log("当前区块高度:", block);
}

main();
