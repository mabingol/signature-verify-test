import {expect} from "chai";
import {network} from "hardhat";

const {ethers} = await network.connect();
import {randomBytes} from "crypto";
// @ts-ignore
import * as secp from "@noble/secp256k1";

// --- helpers ---
const bytesToBigInt = (b: Uint8Array | Buffer): bigint => BigInt("0x" + Buffer.from(b).toString("hex"));
const toHex = (b: Uint8Array | Buffer): `0x${string}` => ("0x" + Buffer.from(b).toString("hex")) as `0x${string}`;

function challenge(Rcomp: Uint8Array, m: Uint8Array, publicKeyComp: Uint8Array): bigint {
    // Uncompress R and derive its Ethereum address like in the contract helper
    const R_uncomp = secp.Point.fromBytes(Rcomp).toBytes(false); // 65 bytes: 0x04||X||Y
    const xy = R_uncomp.slice(1); // drop 0x04, keep 64 bytes
    const R_hash = ethers.keccak256(toHex(xy));
    const R_addr = ethers.getAddress("0x" + R_hash.slice(26)); // last 20 bytes as address

    const parity: number = publicKeyComp[0] + 27 - 2; // 27 or 28
    const pxHex = toHex(publicKeyComp.slice(1, 33));
    const mHex = toHex(m);

    // e = keccak256(address(R) || parity || px || m) via Solidity-packed Keccak
    const eHex = ethers.solidityPackedKeccak256(
        ["address", "uint8", "bytes32", "bytes32"],
        [R_addr, parity, pxHex, mHex]
    );
    return BigInt(eHex);
}

function sign(m: Uint8Array, x: Uint8Array) {
    const publicKey = secp.getPublicKey(x, true); // compressed (33 bytes)

    // k must be a valid scalar; regenerate until valid
    let k: Uint8Array;
    do {
        k = randomBytes(32);
    } while (!secp.utils.isValidSecretKey(k));

    const R = secp.getPublicKey(k, true); // compressed (33 bytes)

    const eBI = challenge(R, m, publicKey);
    const n = secp.Point.CURVE().n;
    const xBI = bytesToBigInt(x);
    const kBI = bytesToBigInt(k);

    // s = k + x*e (mod n)
    const sBI = (kBI + (xBI * (eBI % n)) % n) % n;

    return {R, s: sBI, e: eBI};
}

describe("Schnorr", function () {
    it("verify function", async function () {
        const schnorrContract = await ethers.deployContract("Schnorr");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();

        // generate a valid private key
        let privKey: Uint8Array;
        do {
            privKey = randomBytes(32);
        } while (!secp.utils.isValidSecretKey((privKey)));

        const publicKey = secp.getPublicKey(privKey, true); // compressed

        // message (32 bytes)
        const m = randomBytes(32);

        const sig = sign(m, privKey);

        const parity = publicKey[0] - 2 + 27; // 27 or 28
        const pxBI = bytesToBigInt(publicKey.slice(1, 33));
        const mBI = bytesToBigInt(m);


        const pxB32 = ethers.toBeHex(pxBI);
        const mB32 = ethers.toBeHex(mBI);
        const eB32 = ethers.toBeHex(sig.e);
        const sB32 = ethers.toBeHex(sig.s);

        const ret = await schnorrContract.measureVerify.staticCall(parity, pxB32, mB32, eB32, sB32);
        const cold = ret[0];
        const warm = ret[1];
        console.log("verify gas (cold):", cold.toString());
        console.log("verify gas (warm):", warm.toString());

        expect(
            await schnorrContract.verify(parity, pxB32, mB32, eB32, sB32)
        ).to.equal(true);
    });
});
