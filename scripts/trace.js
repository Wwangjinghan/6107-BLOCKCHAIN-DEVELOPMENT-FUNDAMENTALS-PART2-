import fs from "node:fs";

const txHash = "0x881460eeeaae864c1ece21d8fa760b60a45365de75e62095e851f7746dd3f26c";

async function main() {
  const res = await fetch("http://127.0.0.1:8545", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "debug_traceTransaction",
      params: [txHash],
      id: 1,
    }),
  });

  const data = await res.json();
  fs.writeFileSync("trace.json", JSON.stringify(data, null, 2));
  console.log("saved trace.json");
  console.log("structLogs length:", data.result.structLogs.length);
}

main();
