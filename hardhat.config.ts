import "@nomicfoundation/hardhat-viem";

export default {
    solidity: "0.8.28",
    networks: {
        sepolia: {
            type: "http", // ⚠️ 必须加
            chain: {
                id: 11155111,
                name: "sepolia",
            },
            url: "https://rpc.ankr.com/sepolia", // 或者 Infura / Alchemy URL
            accounts: ["ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"], // 测试币钱包私钥
        },
    },
};
