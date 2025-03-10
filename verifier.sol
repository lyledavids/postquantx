
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Verifier {
    function verifyProof(uint256[8] calldata) external pure returns (bool) {
        return true; // Accepts all proofs (for testing)
    }
}
