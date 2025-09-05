import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("ForstModule", (m) => {
  const counter = m.contract("Frost");

  m.call(counter, "verify", [5n]);

  return { counter };
});
