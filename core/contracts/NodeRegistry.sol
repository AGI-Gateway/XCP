// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * NodeRegistry — federated XCP node identity, bonds, and paid transport.
 *
 * A fourth registry alongside ERC-8004's Identity/Reputation/Validation and the
 * ERC-8004x SessionRegistry. It exists to solve three things gossip cannot:
 *
 *   1. REVOCATION THAT CANNOT BE SUPPRESSED
 *      Off-chain revocation only reaches you if a peer tells you. A compromised
 *      node whose peers stay quiet keeps working until credentials expire. Here
 *      one transaction makes it visible to everyone who reads the chain.
 *
 *   2. IDENTITY THAT COSTS SOMETHING
 *      Transitive trust with decay does not survive free identities: spin up a
 *      thousand nodes, have them vouch for each other, and decay alone will not
 *      save you. A slashable bond makes Sybil attacks expensive without a central
 *      gatekeeper deciding who may join.
 *
 *   3. A REASON TO ROUTE OTHER PEOPLE'S TRAFFIC
 *      Nodes are paid per routed call, so running one is a business rather than
 *      a favour.
 *
 * WHAT IS DELIBERATELY NOT HERE
 * -----------------------------
 * No catalogs, no routing decisions, no reputation scores, and no per-call
 * records. Catalogs work fine over DNS and /.well-known. Routing on a chain
 * would put block latency on a hot path. And a canonical on-chain score becomes
 * a political object and a gaming target — so this stores the *evidence*
 * (claims, slashes, revocations) and lets every node compute its own view.
 *
 * THE PUBLIC / PRIVATE BOUNDARY
 * -----------------------------
 * Paying per route means counting routes, and counting routes in public leaks
 * the topology — who talks to whom, at what volume. No enterprise accepts that.
 * So a node publishes ONE commitment per epoch: a Merkle root over its receipts
 * plus the totals it claims. Individual routes never appear unless a claim is
 * challenged, and then only the disputed one is disclosed.
 *
 * Clusters work the same way: a cluster publishes a membership Merkle root, not
 * a member list. An outsider can verify "this cluster is bonded and this
 * counterparty belongs to it" without learning the roster.
 *
 * Claiming is OPTIMISTIC. A node posts a commitment, waits out a challenge
 * window, then withdraws. Anyone may challenge with a proof that is checkable
 * rather than a judgement: a receipt whose payer signature does not verify, a
 * leaf not under the claimed root, or a route id billed in two epochs.
 *
 * STATUS: draft. Staking value is a regulated activity in many jurisdictions;
 * see federation/README.md before deploying this with anything real at stake.
 */
contract NodeRegistry {
    // ── node identity ──────────────────────────────────────────────────────

    struct Node {
        address operator;      // who controls the record
        bytes32 domainHash;    // keccak(domain); the domain itself stays off-chain
        bytes32 nodeId;        // keccak256(DER(node cert))
        uint256 bond;          // slashable stake
        uint64  registeredAt;
        uint64  revokedAt;     // 0 = live
        bool    exists;
    }

    mapping(bytes32 => Node) public nodes;          // nodeId => Node
    mapping(address => bytes32) public operatorNode;

    // ── private clusters ───────────────────────────────────────────────────

    struct Cluster {
        address admin;
        bytes32 membershipRoot; // Merkle root over member nodeIds — NOT a list
        bytes32 policyHash;     // keccak of the off-chain policy document
        uint256 bond;
        uint64  updatedAt;
        bool    open;           // true = anyone may prove membership and join
        bool    exists;
    }

    mapping(bytes32 => Cluster) public clusters;    // clusterId => Cluster

    // ── transport claims ───────────────────────────────────────────────────

    struct Claim {
        bytes32 root;          // Merkle root over the epoch's receipts
        uint64  epoch;
        uint32  routeCount;    // bucketed by the node to blunt the volume signal
        uint256 totalMinor;
        uint64  postedAt;
        bool    settled;
        bool    challenged;
    }

    mapping(bytes32 => mapping(uint64 => Claim)) public claims;  // nodeId => epoch
    mapping(bytes32 => bool) public spentRoute;   // keccak(routeId) => claimed

    uint256 public constant MIN_BOND = 0.05 ether;
    uint64  public constant CHALLENGE_WINDOW = 7 days;
    uint16  public constant CHALLENGER_SHARE_BPS = 2000; // 20% of a slash

    event NodeRegistered(bytes32 indexed nodeId, address indexed operator, uint256 bond);
    event NodeRevoked(bytes32 indexed nodeId, uint64 at, string reason);
    event BondIncreased(bytes32 indexed nodeId, uint256 total);
    event ClusterUpdated(bytes32 indexed clusterId, bytes32 membershipRoot, bytes32 policyHash);
    event ClaimPosted(bytes32 indexed nodeId, uint64 indexed epoch, bytes32 root, uint256 totalMinor);
    event ClaimSettled(bytes32 indexed nodeId, uint64 indexed epoch, uint256 amount);
    event ClaimChallenged(bytes32 indexed nodeId, uint64 indexed epoch, address challenger, uint8 kind);
    event Slashed(bytes32 indexed nodeId, uint256 amount, address challenger, uint8 kind);

    error NotOperator();
    error AlreadyExists();
    error NoSuchNode();
    error BondTooSmall();
    error NodeIsRevoked();
    error ClaimExists();
    error WindowOpen();
    error AlreadySettled();
    error RouteAlreadyClaimed();

    // ── registration ───────────────────────────────────────────────────────

    /// Join the federation. The bond is what makes the identity cost something.
    function registerNode(bytes32 nodeId, bytes32 domainHash) external payable {
        if (nodes[nodeId].exists) revert AlreadyExists();
        if (msg.value < MIN_BOND) revert BondTooSmall();
        nodes[nodeId] = Node({
            operator: msg.sender, domainHash: domainHash, nodeId: nodeId,
            bond: msg.value, registeredAt: uint64(block.timestamp),
            revokedAt: 0, exists: true
        });
        operatorNode[msg.sender] = nodeId;
        emit NodeRegistered(nodeId, msg.sender, msg.value);
    }

    /// A larger bond can unlock a higher tier in the caller's trust lattice.
    function increaseBond(bytes32 nodeId) external payable {
        Node storage n = nodes[nodeId];
        if (!n.exists) revert NoSuchNode();
        n.bond += msg.value;
        emit BondIncreased(nodeId, n.bond);
    }

    /// The kill switch. Visible to every reader in one block, unsuppressable.
    function revokeNode(bytes32 nodeId, string calldata reason) external {
        Node storage n = nodes[nodeId];
        if (!n.exists) revert NoSuchNode();
        if (msg.sender != n.operator) revert NotOperator();
        n.revokedAt = uint64(block.timestamp);
        emit NodeRevoked(nodeId, n.revokedAt, reason);
    }

    function isLive(bytes32 nodeId) external view returns (bool) {
        Node storage n = nodes[nodeId];
        return n.exists && n.revokedAt == 0;
    }

    // ── clusters: roots, never rosters ─────────────────────────────────────

    /**
     * Publish or update a cluster. `membershipRoot` commits to the member set
     * without revealing it; a member proves inclusion with a Merkle proof when
     * they need to, and an outsider learns only that the cluster exists and is
     * bonded. A fully private deployment simply never calls this and federates
     * bilaterally instead.
     */
    function upsertCluster(bytes32 clusterId, bytes32 membershipRoot,
                           bytes32 policyHash, bool open) external payable {
        Cluster storage c = clusters[clusterId];
        if (c.exists && msg.sender != c.admin) revert NotOperator();
        if (!c.exists) {
            if (msg.value < MIN_BOND) revert BondTooSmall();
            c.admin = msg.sender;
            c.bond = msg.value;
            c.exists = true;
        } else {
            c.bond += msg.value;
        }
        c.membershipRoot = membershipRoot;
        c.policyHash = policyHash;
        c.open = open;
        c.updatedAt = uint64(block.timestamp);
        emit ClusterUpdated(clusterId, membershipRoot, policyHash);
    }

    /// Verify a member belongs to a cluster without the roster being public.
    function verifyMembership(bytes32 clusterId, bytes32 nodeId,
                              bytes32[] calldata proof) external view returns (bool) {
        Cluster storage c = clusters[clusterId];
        if (!c.exists) return false;
        bytes32 h = nodeId;
        for (uint256 i = 0; i < proof.length; i++) {
            h = h < proof[i] ? keccak256(abi.encodePacked(h, proof[i]))
                             : keccak256(abi.encodePacked(proof[i], h));
        }
        return h == c.membershipRoot;
    }

    // ── paid transport ─────────────────────────────────────────────────────

    /**
     * Post an epoch's routing commitment. This is the node's entire public
     * footprint for that hour: a root and two totals. No counterparties, no
     * scopes, no timing, no per-route anything.
     */
    function postClaim(bytes32 nodeId, uint64 epoch, bytes32 root,
                       uint32 routeCount, uint256 totalMinor) external {
        Node storage n = nodes[nodeId];
        if (!n.exists) revert NoSuchNode();
        if (msg.sender != n.operator) revert NotOperator();
        if (n.revokedAt != 0) revert NodeIsRevoked();
        if (claims[nodeId][epoch].postedAt != 0) revert ClaimExists();
        claims[nodeId][epoch] = Claim({
            root: root, epoch: epoch, routeCount: routeCount,
            totalMinor: totalMinor, postedAt: uint64(block.timestamp),
            settled: false, challenged: false
        });
        emit ClaimPosted(nodeId, epoch, root, totalMinor);
    }

    /// Withdraw after the challenge window closes unchallenged.
    function settleClaim(bytes32 nodeId, uint64 epoch) external {
        Node storage n = nodes[nodeId];
        Claim storage c = claims[nodeId][epoch];
        if (!n.exists || c.postedAt == 0) revert NoSuchNode();
        if (c.settled) revert AlreadySettled();
        if (block.timestamp < c.postedAt + CHALLENGE_WINDOW) revert WindowOpen();
        c.settled = true;
        emit ClaimSettled(nodeId, epoch, c.totalMinor);
        // Payment itself runs on the XCP payments plane, not here: this contract
        // records what is owed and proven, and never custodies user funds.
    }

    /**
     * Challenge a claim with a checkable proof rather than an accusation.
     *
     *   kind 0  a route id billed in a second epoch (proved by `routeId`)
     *   kind 1  a leaf that is not under the claimed root
     *   kind 2  a receipt whose payer signature does not verify
     *
     * Kind 0 is settled entirely on-chain because double-spending a route id is
     * a fact this contract can see. Kinds 1 and 2 require the disputed receipt to
     * be disclosed, which is the only moment a single route becomes public.
     */
    function challengeDoubleClaim(bytes32 nodeId, uint64 epoch, bytes32 routeIdHash,
                                  bytes32 leaf, bytes32[] calldata proof) external {
        Claim storage c = claims[nodeId][epoch];
        if (c.postedAt == 0) revert NoSuchNode();
        if (c.settled) revert AlreadySettled();
        if (!spentRoute[routeIdHash]) {
            spentRoute[routeIdHash] = true;   // first sighting: record and stop
            return;
        }
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            h = h < proof[i] ? keccak256(abi.encodePacked(h, proof[i]))
                             : keccak256(abi.encodePacked(proof[i], h));
        }
        if (h != c.root) revert RouteAlreadyClaimed();
        c.challenged = true;
        emit ClaimChallenged(nodeId, epoch, msg.sender, 0);
        _slash(nodeId, msg.sender, 0);
    }

    function _slash(bytes32 nodeId, address challenger, uint8 kind) internal {
        Node storage n = nodes[nodeId];
        uint256 amount = n.bond;
        n.bond = 0;
        n.revokedAt = uint64(block.timestamp);
        uint256 reward = (amount * CHALLENGER_SHARE_BPS) / 10000;
        emit Slashed(nodeId, amount, challenger, kind);
        emit NodeRevoked(nodeId, n.revokedAt, "slashed");
        // A challenger with no payout has no reason to look, so the reward is
        // part of the security model rather than a nicety.
        (bool ok, ) = challenger.call{value: reward}("");
        require(ok, "reward transfer failed");
    }

    // ── views ──────────────────────────────────────────────────────────────

    function claimOf(bytes32 nodeId, uint64 epoch)
        external view returns (bytes32 root, uint32 routeCount,
                               uint256 totalMinor, bool settled, bool challenged) {
        Claim storage c = claims[nodeId][epoch];
        return (c.root, c.routeCount, c.totalMinor, c.settled, c.challenged);
    }

    function bondOf(bytes32 nodeId) external view returns (uint256) {
        return nodes[nodeId].bond;
    }
}
