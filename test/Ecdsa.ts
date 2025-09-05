import {expect} from "chai";
import {network} from "hardhat";

const {ethers} = await network.connect();

import {
    keccak256,
    toUtf8Bytes,
    getBytes,
    TypedDataEncoder,
    SigningKey,
    Signature,
    toBeHex,
} from "ethers";

describe("VerifySignature", () => {
    let verify: any;

    // secp256k1 order (for crafting a high-s negative test)
    const N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

    before(async () => {
        const Verify = await ethers.getContractFactory("Ecdsa");
        verify = await Verify.deploy();
        await verify.waitForDeployment();
    });

    it("verifies raw 32-byte hash via verifyHash()", async () => {
        // Use an offline wallet purely for signing
        const wallet = ethers.Wallet.createRandom();

        // Create a 32-byte message hash (this digest goes directly to ecrecover)
        const m = keccak256(toUtf8Bytes("hello raw-hash"));

        // Sign the raw digest (no prefix). Use SigningKey to avoid EIP-191 prefixing.
        const sk = new SigningKey(wallet.privateKey);
        // Optional: capture the correct recovery param to assert locally
        const sig = sk.sign(m); // returns a normalized low-s signature
        const r = sig.r; // 0x-prefixed 32-byte hex
        const s = sig.s;

        const ok = await verify.verifyHash(wallet.address, m, r, s);
        expect(ok).to.equal(true);

        // Negative: flip to high-s -> contract enforces EIP-2 low-s and must fail
        const sBig = BigInt(s);
        const sHigh = toBeHex(N - sBig, 32);
        const bad = await verify.verifyHash(wallet.address, m, r, sHigh);
        expect(bad).to.equal(false);
    });

    it("verifies EIP-191 (personal_sign) via verifyPersonalSign()", async () => {
        const wallet = ethers.Wallet.createRandom();

        // Raw 32-byte M (NOT prefixed); contract will prefix internally.
        const m = keccak256(toUtf8Bytes("hello personal_sign"));

        // IMPORTANT: sign the 32 raw bytes so the prefix length is 32
        const sigHex = await wallet.signMessage(getBytes(m));
        const sig = Signature.from(sigHex);
        const v :number = sig.v;
        const ok = await verify.verifyPersonalSign(wallet.address, v,m, sig.r, sig.s);
        expect(ok).to.equal(true);

        const ret = await verify.measureVerify.staticCall(wallet.address,v, m, sig.r, sig.s);
        const cold = ret[0];
        const warm = ret[1];
        console.log("verify gas (cold):", cold.toString());
        console.log("verify gas (warm):", warm.toString());

        // Negative: tamper m
        const m2 = keccak256(toUtf8Bytes("tampered"));
        const bad = await verify.verifyPersonalSign(wallet.address, v, m2, sig.r, sig.s);
        expect(bad).to.equal(false);




    });

    it("verifies EIP-712 typed data via verifyTypedData()", async () => {
        const wallet = ethers.Wallet.createRandom();

        // Simple Mail type (classic example)
        const types = {
            Mail: [
                { name: "from", type: "address" },
                { name: "to", type: "address" },
                { name: "contents", type: "string" },
            ],
        } as const;

        const value = {
            from: wallet.address,
            to: ethers.ZeroAddress,
            contents: "gm 712",
        };

        const { chainId } = await ethers.provider.getNetwork();

        const domain = {
            name: "MyDApp",
            version: "1",
            chainId: Number(chainId),
            // Not strictly required by the contract, but good hygiene:
            verifyingContract: verify.target as string,
        };

        // Sign typed data (offline)
        const sigHex = await wallet.signTypedData(domain, types, value);
        const sig = Signature.from(sigHex);

        // Compute domainSeparator and structHash exactly as the signer did
        const domainSeparator = TypedDataEncoder.hashDomain(domain);
        const structHash = TypedDataEncoder.from(types).hash(value);

        const ok = await verify.verifyTypedData(
            wallet.address,
            domainSeparator,
            structHash,
            sig.r,
            sig.s
        );
        expect(ok).to.equal(true);

        // Negative: change structHash
        const structHashBad = TypedDataEncoder.from(types).hash({
            ...value,
            contents: "altered",
        });
        const bad = await verify.verifyTypedData(
            wallet.address,
            domainSeparator,
            structHashBad,
            sig.r,
            sig.s
        );
        expect(bad).to.equal(false);
    });
});
