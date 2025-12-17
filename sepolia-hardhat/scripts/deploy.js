async function main() {
  const FileRegistry = await ethers.getContractFactory("FileRegistry");
  const fileRegistry = await FileRegistry.deploy();

  await fileRegistry.waitForDeployment();

  console.log("FileRegistry deployed to:", await fileRegistry.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
