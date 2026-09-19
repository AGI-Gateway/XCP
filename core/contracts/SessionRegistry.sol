// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISessionRegistry (ERC-8004x)
/// @notice The fourth registry of the ERC-8004x fork: binds an agent's
///         on-chain identity to a live mTLS session via the certificate
///         footprint keccak256(DER(cert)). ~200 bytes per binding; hashes
///         only, no PII. See the fork proposal for the full spec.
interface ISessionRegistry {
    struct SessionBinding {
        uint256 agentId;        // ERC-8004 Identity Registry token ID
        bytes32 certFootprint;  // keccak256(DER(X.509 client cert))
        uint64  notBefore;
        uint64  notAfter;       // MUST be <= notBefore + 7 days
        bytes32 mandateRoot;    // Merkle root of active governance mandates
        bytes32 railsBitmap;    // enabled payment rails (bit0=x402,1=AP2,2=MPP,3=ACP)
        bool    revoked;
    }

    event SessionBound(bytes32 indexed sessionId, uint256 indexed agentId,
                       bytes32 certFootprint, uint64 notAfter);
    event SessionRevoked(bytes32 indexed sessionId, uint256 indexed agentId);
    event MandateRootUpdated(bytes32 indexed sessionId, bytes32 newRoot);

    function bindSession(uint256 agentId, bytes32 certFootprint, uint64 notAfter,
                         bytes32 mandateRoot, bytes32 railsBitmap)
        external returns (bytes32 sessionId);

    function revokeSession(bytes32 sessionId) external;

    function updateMandateRoot(bytes32 sessionId, bytes32 newRoot) external;

    /// @notice The hot-path read the XCP verifier calls on every request.
    function verifySession(bytes32 certFootprint)
        external view
        returns (bool valid, uint256 agentId,
                 bytes32 mandateRoot, bytes32 railsBitmap);
}

/// @title SessionRegistry — minimal reference implementation
/// @notice Lean by design: stores the binding struct keyed by footprint, plus
///         a footprint index by sessionId for revocation/update. No upgrade
///         proxy, no access list beyond the binder + registered guardians —
///         this is the spec-faithful skeleton the verifier reads.
contract SessionRegistry is ISessionRegistry {
    uint64 public constant MAX_TTL = 7 days;

    // footprint => binding
    mapping(bytes32 => SessionBinding) private _byFootprint;
    // sessionId => footprint (for revoke/update by id)
    mapping(bytes32 => bytes32) private _footprintOf;
    // sessionId => controller (the address that bound it)
    mapping(bytes32 => address) public controllerOf;
    // agentId => controller (set on first bind; a real deployment ties this to
    // the ERC-8004 Identity Registry — here we trust first-binder for the demo)
    mapping(uint256 => address) public agentController;
    // guardians who may revoke on an agent's behalf (human sponsors)
    mapping(uint256 => mapping(address => bool)) public isGuardian;

    function bindSession(
        uint256 agentId,
        bytes32 certFootprint,
        uint64 notAfter,
        bytes32 mandateRoot,
        bytes32 railsBitmap
    ) external returns (bytes32 sessionId) {
        require(certFootprint != bytes32(0), "footprint=0");
        require(notAfter > block.timestamp, "expired");
        require(notAfter <= block.timestamp + MAX_TTL, "ttl>7d");

        // Bind agent->controller on first use; afterwards only that controller
        // (or a guardian) may bind/rotate for the agent.
        address ctrl = agentController[agentId];
        if (ctrl == address(0)) {
            agentController[agentId] = msg.sender;
        } else {
            require(msg.sender == ctrl || isGuardian[agentId][msg.sender],
                    "not agent controller");
        }

        sessionId = keccak256(abi.encodePacked(agentId, certFootprint, notAfter));
        _byFootprint[certFootprint] = SessionBinding({
            agentId: agentId,
            certFootprint: certFootprint,
            notBefore: uint64(block.timestamp),
            notAfter: notAfter,
            mandateRoot: mandateRoot,
            railsBitmap: railsBitmap,
            revoked: false
        });
        _footprintOf[sessionId] = certFootprint;
        controllerOf[sessionId] = msg.sender;
        emit SessionBound(sessionId, agentId, certFootprint, notAfter);
    }

    function revokeSession(bytes32 sessionId) external {
        bytes32 fp = _footprintOf[sessionId];
        require(fp != bytes32(0), "unknown session");
        SessionBinding storage b = _byFootprint[fp];
        require(
            msg.sender == controllerOf[sessionId] ||
            isGuardian[b.agentId][msg.sender],
            "not authorized"
        );
        b.revoked = true;
        emit SessionRevoked(sessionId, b.agentId);
    }

    function updateMandateRoot(bytes32 sessionId, bytes32 newRoot) external {
        bytes32 fp = _footprintOf[sessionId];
        require(fp != bytes32(0), "unknown session");
        SessionBinding storage b = _byFootprint[fp];
        require(
            msg.sender == controllerOf[sessionId] ||
            isGuardian[b.agentId][msg.sender],
            "not authorized"
        );
        b.mandateRoot = newRoot;
        emit MandateRootUpdated(sessionId, newRoot);
    }

    function addGuardian(uint256 agentId, address guardian) external {
        require(msg.sender == agentController[agentId], "not controller");
        isGuardian[agentId][guardian] = true;
    }

    function verifySession(bytes32 certFootprint)
        external view
        returns (bool valid, uint256 agentId, bytes32 mandateRoot, bytes32 railsBitmap)
    {
        SessionBinding storage b = _byFootprint[certFootprint];
        valid = b.certFootprint != bytes32(0)
            && !b.revoked
            && b.notAfter > block.timestamp
            && b.notBefore <= block.timestamp;
        return (valid, b.agentId, b.mandateRoot, b.railsBitmap);
    }
}
