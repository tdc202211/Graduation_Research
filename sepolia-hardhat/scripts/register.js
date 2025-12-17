async function main() {
  const CONTRACT_ADDRESS = "0x26511B4C9Da665AefC3DDF49A184D46763f0fCCf";

  const FileRegistry = await ethers.getContractFactory("FileRegistry");
  const fileRegistry = FileRegistry.attach(CONTRACT_ADDRESS);

  const tx = await fileRegistry.registerFile(
    "hash_test_001",
    "box_file_id_123",
    "example.pdf"
  );

  console.log("Transaction sent:", tx.hash);

  await tx.wait();

  console.log("FileRegistered event emitted");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
