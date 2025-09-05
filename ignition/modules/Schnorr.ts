import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("SchnorrModule", (m) => {
  const counter = m.contract("Schnorr");

  m.call(counter, "verify", [5n]);

  return { counter };
});
