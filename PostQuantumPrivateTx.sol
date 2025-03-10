// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IVerifier {
    function verifyProof(uint256[8] calldata proof) external view returns (bool);
}

contract PostQuantumPrivateTx is Ownable {
    struct Note {
        bytes commitment;
        bool spent;
    }

    mapping(bytes => Note) public notes;
    IVerifier public starkVerifier;

    event Deposit(bytes commitment);
    event Transfer(bytes commitmentFrom, bytes commitmentTo);
    event Withdrawal(address indexed recipient);

    constructor(address _verifier) Ownable(msg.sender) {
        starkVerifier = IVerifier(_verifier);
    }

    function deposit(bytes memory commitment) external payable {
        require(msg.value > 0, "Deposit must be nonzero");
        require(notes[commitment].commitment.length == 0, "Commitment exists");

        notes[commitment] = Note(commitment, false);
        emit Deposit(commitment);
    }

    function transfer(bytes memory commitmentFrom, bytes memory commitmentTo, uint256[8] calldata starkProof) external {
        require(!notes[commitmentFrom].spent, "Already spent");
        require(starkVerifier.verifyProof(starkProof), "Invalid STARK proof");

        notes[commitmentFrom].spent = true;
        notes[commitmentTo] = Note(commitmentTo, false);

        emit Transfer(commitmentFrom, commitmentTo);
    }

    function withdraw(bytes memory commitment, uint256[8] calldata starkProof) external {
        require(!notes[commitment].spent, "Already spent");
        require(starkVerifier.verifyProof(starkProof), "Invalid STARK proof");

        notes[commitment].spent = true;
        payable(msg.sender).transfer(address(this).balance);

        emit Withdrawal(msg.sender);
    }
}
