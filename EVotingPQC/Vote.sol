
pragma solidity ^0.8.0;

contract Vote {
    mapping(address => bool) public hasVoted;
    event Voted(address voter, bytes cipher, bytes signature);

    //test func -- still need to deply this
    function castVote(bytes calldata cipher, bytes calldata sig) external {
        require(!hasVoted[msg.sender], "Already voted");
        hasVoted[msg.sender] = true;
        emit Voted(msg.sender, cipher, sig);
    }
}
