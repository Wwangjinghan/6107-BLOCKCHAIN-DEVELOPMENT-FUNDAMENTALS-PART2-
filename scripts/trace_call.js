const txHash = "0x881460eeeaae864c1ece21d8fa760b60a45365de75e62095e851f7746dd3f26c";

async function main() {
  const res = await fetch("http://127.0.0.1:8545", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "debug_traceTransaction",
      params: [
        txHash,
        { tracer: "callTracer" }
      ],
      id: 1,
    }),
  });

  const data = await res.json();
  // 先看 HTTP 状态码 & 整包返回
  console.log("HTTP status:", res.status);
  console.log("keys:", Object.keys(data));
  console.log("RPC error:", data.error);
  console.log("RPC result type:", typeof data.result);

// 只打印前 800 字符，避免刷屏
  console.log("raw:", JSON.stringify(data).slice(0, 800));

}

main();
