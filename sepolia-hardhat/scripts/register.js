const hre = require("hardhat");

async function main() {
  // Usage:
  //   CONTRACT_ADDR=0x... npx hardhat run scripts/register.js --network <network> -- <sha256hex> <boxIdOrUrl> <fileName>
  const args = process.argv.slice(2);
  // hardhat adds its own args; values come after "--"
  const [sha256hex, boxIdOrUrl, fileName] = args.slice(-3);

  if (!sha256hex || !boxIdOrUrl || !fileName) {
    console.error("Usage: CONTRACT_ADDR=0x... npx hardhat run scripts/register.js --network <network> -- <sha256hex> <boxIdOrUrl> <fileName>");
    process.exit(1);
  }

  const contractAddr = process.env.CONTRACT_ADDR;
  if (!contractAddr) {
    console.error("CONTRACT_ADDR is not set");
    process.exit(1);
  }

  const FileRegistry = await hre.ethers.getContractFactory("FileRegistry");
  const fileRegistry = FileRegistry.attach(contractAddr);

  // bytes32 expects 32 bytes. sha256 hex should be 64 chars.
  const hash = "0x" + sha256hex.replace(/^0x/, "");
  const tx = await fileRegistry.recordFile(hash, boxIdOrUrl, fileName);

  console.log("Transaction sent:", tx.hash);
  await tx.wait();
  console.log("done");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
