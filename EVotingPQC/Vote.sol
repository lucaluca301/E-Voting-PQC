// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

/// @title Post-Quantum Ballot Storage (Kyber + AES-GCM + Dilithium)
/// @author  Luca  –  Master's dissertation PoC
contract PQCBallotStore {
    // Type

    struct Ballot {
        bytes ctKEM;   // Kyber-512 ciphertext (800-ish B)
        bytes iv;      // 12-byte AES-GCM IV
        bytes cipher;  // AES-GCM ciphertext (vote)
        bytes tag;     // 16-byte GCM auth-tag
        bytes sig;     // Dilithium-2 signature on (ctKEM‖iv‖cipher‖tag)
    }

    // Storage

    address public immutable admin;                     // deployer
    mapping(address => bool)     public tallyAuth;      // tally servers
    mapping(address => bool)     public hasVoted;       // 1-vote rule
    mapping(address => Ballot)   private ballotOf;      // lookup
    Ballot[]                     private allBallots;    // enumeration

    // Events

    event VoteCast(
        address indexed voter,
        bytes   ctKEM,
        bytes   iv,
        bytes   cipher,
        bytes   tag,
        bytes   sig
    );

    event VoteInvalidated(address indexed voter);

    // Constructor

    constructor() {
        admin              = msg.sender;
        tallyAuth[msg.sender] = true;   // deployer trusted by default
    }

    // Admin Tally operations

    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }
    modifier onlyTally() { require(tallyAuth[msg.sender], "not tally"); _; }

    function addTally(address acct) external onlyAdmin {
        tallyAuth[acct] = true;
    }
    function removeTally(address acct) external onlyAdmin {
        tallyAuth[acct] = false;
    }

    // Voting API

    /// @dev  reverts if sender already voted
    function castVote(
        bytes calldata ctKEM,
        bytes calldata iv,
        bytes calldata cipher,
        bytes calldata tag,
        bytes calldata sig
    ) external {
        require(!hasVoted[msg.sender], "already voted");

        Ballot memory b = Ballot(ctKEM, iv, cipher, tag, sig);
        hasVoted[msg.sender] = true;
        ballotOf[msg.sender] = b;
        allBallots.push(b);

        emit VoteCast(msg.sender, ctKEM, iv, cipher, tag, sig);
    }

    /// @notice called off-chain after Dilithium sig verification fails
    function invalidateVote(address voter) external onlyTally {
        require(hasVoted[voter], "no vote");
        delete ballotOf[voter];
        hasVoted[voter] = false;
        emit VoteInvalidated(voter);
    }

    // View helpers

    function ballotsCount() external view returns (uint256) {
        return allBallots.length;
    }
    function getBallot(uint256 idx)
        external view
        returns (Ballot memory)
    {
        return allBallots[idx];
    }
}
