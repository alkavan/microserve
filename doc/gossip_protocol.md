The Gossip protocol enables nodes to share cluster state information in a decentralized way.
Below is a simplified flow of messages illustrating how nodes use Gossip to discover each other and maintain the cluster state.
This example assumes a cluster with three nodes (Node A, Node B, Node C) and focuses on basic state dissemination.

## Simple Gossip Protocol Message Flow

1. **Initialization (Node A starts)**
    - Node A is online and knows only about itself.
    - It maintains a **gossip state** (e.g., its IP, status: UP, generation number: 1).
    - Node A selects a random node (say, Node B) from its seed list (pre-configured nodes for bootstrapping).

2. **Gossip Round 1: Node A → Node B**
    - **Message**: Node A sends a **Gossip Digest Syn** to Node B.
        - Contains: A's endpoint state (IP, generation number, heartbeat).
        - Example: `{Node A: {IP: 192.168.1.1, Gen: 1, Heartbeat: 100}}`.
    - **Purpose**: Ask Node B for its view of the cluster state and share A's state.

3. **Node B Responds: Node B → Node A**
    - Node B receives the Syn and compares it with its own state.
        - Node B's state: `{Node B: {IP: 192.168.1.2, Gen: 1, Heartbeat: 50}, Node C: {IP: 192.168.1.3, Gen: 1, Heartbeat: 80}}`.
    - **Message**: Node B sends a **Gossip Digest Ack** to Node A.
        - Contains: Nodes where B has newer info (e.g., Node C) and requests for nodes where A has newer info (e.g., Node A).
        - Example: `{Node C: {IP: 192.168.1.3, Gen: 1, Heartbeat: 80}, Request: Node A}`.
    - **Purpose**: Share Node C’s state and request A’s updated state.

4. **Node A Updates and Responds: Node A → Node B**
    - Node A processes the Ack, learning about Node C.
    - **Message**: Node A sends a **Gossip Digest Ack2** to Node B.
        - Contains: Updated state for Node A.
        - Example: `{Node A: {IP: 192.168.1.1, Gen: 1, Heartbeat: 101}}`.
    - **Purpose**: Complete the exchange by sending the requested state.

5. **Gossip Round 2: Node A → Node C**
    - Node A, now aware of Node C, initiates gossip with it.
    - **Message**: Node A sends a **Gossip Digest Syn** to Node C.
        - Contains: `{Node A: {IP: 192.168.1.1, Gen: 1, Heartbeat: 102}, Node B: {IP: 192.168.1.2, Gen: 1, Heartbeat: 50}}`.
    - Node C responds similarly with a **Gossip Digest Ack**, sharing its state and any newer info (e.g., about Node B).

6. **Periodic Gossip**
    - Each node (A, B, C) repeats this process periodically (e.g., every second).
    - Nodes randomly select peers to gossip with, ensuring all nodes eventually converge on a consistent view of the cluster.
    - Example: Node B might gossip with Node C, sharing Node A’s state, and so on.

### Key Points
- **Messages**:
    - **Gossip Digest Syn**: Initiates gossip, sharing a summary of known states.
    - **Gossip Digest Ack**: Responds with newer states and requests missing info.
    - **Gossip Digest Ack2**: Finalizes the exchange with requested states.
- **State Updates**: Nodes update their local state if they receive newer information (based on generation number or heartbeat).
- **Convergence**: Over time, all nodes learn about each other (e.g., IPs, status) and detect failures (e.g., if heartbeats stop incrementing).

### Simplified Diagram
```
Node A                 Node B              Node C
  |  Syn (A's state)  →  |                   |
  |                   ← Ack (C, req A)       |
  |  Ack2 (A's state) →  |                   |
  |  Syn (A, B)       →  |    Syn (B, C)   → |
  |                   ←       Ack (B, C)   ← |
  ... (continues periodically) ...
```

This flow ensures nodes efficiently share and synchronize cluster state (e.g., node IPs, status) without requiring a central coordinator, making the protocol scalable and resilient.
