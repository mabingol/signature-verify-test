// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Ecdsa {
    // secp256k1n/2
    uint256 internal constant _HALF_ORDER =
    0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function toEthSignedMessageHash(bytes32 m) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", m));
    }

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @dev The key fix: check BOTH v values against the expected signer.
    function isValidSig(address expected, bytes32 m, bytes32 r, bytes32 s) internal pure returns (bool) {
        uint256 rU = uint256(r);
        uint256 sU = uint256(s);
        if (rU == 0 || sU == 0 || sU > _HALF_ORDER) return false;
        if (ecrecover(m, 27, r, s) == expected) return true;
        if (ecrecover(m, 28, r, s) == expected) return true;
        return false;
    }
    /// @dev The key fix: check BOTH v values against the expected signer.
    function isValidSig2(address expected, uint8 v, bytes32 m, bytes32 r, bytes32 s) internal pure returns (bool) {
        uint256 rU = uint256(r);
        uint256 sU = uint256(s);
        if (rU == 0 || sU == 0 || sU > _HALF_ORDER) return false;
        if (ecrecover(m, v, r, s) == expected) return true;
        return false;
    }

    /// @notice raw 32-byte digest check
    function verifyHash(address expectedSigner, bytes32 m, bytes32 r, bytes32 s)
    public pure
    returns (bool)
    {
        return isValidSig(expectedSigner, m, r, s);
    }

    /// @notice EIP-191 (personal_sign) for 32-byte message
    function verifyPersonalSign(address expectedSigner, uint8 v, bytes32 m, bytes32 r, bytes32 s)
    public pure
    returns (bool)
    {
        bytes32 digest = toEthSignedMessageHash(m);
        return isValidSig2(expectedSigner, v,digest, r, s);
    }

    function measureVerify(
        address expectedSigner, uint8 v, bytes32 m, bytes32 r, bytes32 s
    )   external view returns (uint256 cold, uint256 warm) {
        uint256 g0 = gasleft();
        require(verifyPersonalSign(  expectedSigner,   v,m,   r,   s), "cold fail");
        uint256 g1 = gasleft();
        require(verifyPersonalSign(  expectedSigner,   v,m,   r,   s), "warm fail");
        uint256 g2 = gasleft();
        unchecked {
            cold = g0 - g1;
            warm = g1 - g2;
        }
    }

    /// @notice EIP-712
    function verifyTypedData(
        address expectedSigner,
        bytes32 domainSeparator,
        bytes32 structHash,
        bytes32 r,
        bytes32 s
    ) external pure returns (bool) {
        bytes32 digest = toTypedDataHash(domainSeparator, structHash);
        return isValidSig(expectedSigner, digest, r, s);
    }
}
