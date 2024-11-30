# AgentConnect

[中文版](README.cn.md)

## What is AgentConnect

AgentConnect is an open-source implementation of the [Agent Network Protocol (ANP)](https://github.com/chgaowei/AgentNetworkProtocol).

## Vision

In this new era of rapid AI development, we are entering a new epoch of agent networks. Imagine the future: your personal assistant agent seamlessly communicates with restaurant agents when ordering meals; your smart home agent collaborates with energy management agents to optimize power usage; your investment advisor agent exchanges real-time information with global market analysis agents... This is the upcoming era of agent networks.

However, as Bill Gates mentioned in [a blog post](https://www.gatesnotes.com/AI-agents), there is currently no standard protocol that allows agents to communicate with each other. This is the problem that the Agent Network Protocol (ANP) aims to solve.

The vision of the Agent Network Protocol (ANP) is to **define how agents connect with each other and build an open, secure, and efficient collaboration network for billions of agents**. Just as the development of Internet standard protocols enabled the information age of the past three decades, we believe that in the near future, billions of agents will build an unprecedented collaboration network through ANP, creating greater value than the existing Internet. Empowered by AI technology and ANP, the agent network will eventually evolve into a **self-organizing, self-negotiating** efficient collaboration network - an incredibly exciting future.

## Challenges

Agent Network Protocol (ANP) aims to address three major challenges in connectivity:

- How agents authenticate each other to allow any two agents to connect
- How agents establish end-to-end encrypted communication to ensure communication security
- How agents efficiently exchange data to enhance collaboration efficiencynegotiation between agents

## Protocol Architecture

To address these three challenges, the Agent Network Protocol (ANP) is designed as a three-layer architecture, consisting of (from bottom to top) the Identity and Encrypted Communication Layer, Meta-Protocol Layer, and Application Protocol Layer, as shown below:

<p align="center">
  <img src="/images/protocol-layer-design.png" width="50%" alt="Protocol Layer Design"/>
</p>

## AgentConnect Architecture

The technical architecture of AgentConnect is shown in the figure below:

<p align="center">
  <img src="/images/agent-connect-architecture.png" width="50%" alt="Project Architecture"/>
</p>

Corresponding to the three-layer architecture of the Agent Network Protocol, AgentConnect mainly includes the following parts:

1. **Identity Authentication Module and End-to-End Encryption Module**
   Mainly implements identity authentication and end-to-end encrypted communication based on W3C DID, including the generation, verification, and retrieval of DID documents, as well as the implementation of end-to-end encrypted communication schemes based on DID and ECDHE (Elliptic Curve Diffie-Hellman Ephemeral).

2. **Meta-Protocol Module**
   The meta-protocol module needs to be implemented based on LLM (Large Language Model) and meta-protocol, mainly including application protocol negotiation, protocol code implementation, protocol debugging, and protocol processing based on the meta-protocol.

3. **Application Layer Protocol Integration Framework**
   The main purpose is to manage the protocol specification documents and protocol codes for communication with other agents, including application protocol loading, application protocol unloading, application protocol configuration, and application protocol processing. Using this framework, agents can easily and on-demand load the required ready-made protocols, speeding up the agent protocol negotiation process.

In addition to the above functions, AgentConnect will also focus on performance and multi-platform support in the future:

- **Performance**: As a basic code library, we hope to provide extreme performance, and the core part of the code will be rewritten in Rust in the future.
- **Multi-Platform**: Currently supports mac, Linux, and Windows, and will support mobile and browser platforms in the future.

## Contact Us

- email: chgaowei@gmail.com
- Discord: [https://discord.gg/SuXb2pzqGy](https://discord.gg/SuXb2pzqGy)  
- Official Website: [https://www.agent-network-protocol.com/](https://www.agent-network-protocol.com/)  

## Milestones

Whether it is the protocol or the open-source code implementation, we are advancing step by step in the following order:

- Build the identity authentication and end-to-end encrypted communication protocol and implementation. This is the foundation and core of our entire project, and the current protocol design and code are basically complete.
- Design and implement the meta-protocol and meta-protocol code. This will help the agent network evolve into a self-organizing, self-negotiating efficient collaborative network, which is what we are currently working on. This will be an exciting feature, and we expect to release the first version soon.
- Develop the application layer protocol integration framework. This will help the Agent Network Protocol (ANP) provide services for agents in various scenarios.

In addition, we will follow the principle of overall first, then details. In the early stages, we will focus on building the overall architecture, constructing an overall outline for each major module, and getting it up and running quickly, rather than building individual exquisite but non-functional modules.

To promote the Agent Network Protocol (ANP) as an industry standard, we will form the ANP Standardization Committee at an appropriate time, dedicated to promoting ANP as an industry standard recognized by international standardization organizations such as W3C.

Below are the current development features and progress of AgentConnect:

- [x] Initial version development completed, supporting single-node mode and hosted mode
- [ ] DID authentication supports HTTP protocol, which can be easily integrated into protocols such as MCP
- [ ] Replace the core connection protocol with a binary format instead of the current JSON format to improve transmission efficiency
- [ ] Support more data formats: files (images, videos, audio), live streaming, real-time communication (RTC), etc.
- [ ] Design and implement the meta-protocol and layer0 protocol for collaboration between agents based on the Agent Network Protocol
- [ ] Compatible with DID web methods, W3C Verifiable Credentials (VC), and support transactions between DIDs
- [ ] Rewrite AgentConnect in Rust to improve performance and support more platforms: macOS, Linux, iOS, Android
- [ ] Support more encryption algorithms
- [ ] Explore a fully blockchain-based solution

## Installation

```bash
pip install agent-connect
```

### Running

After installing the agent-connect library, you can run our demo to experience the powerful features of agent-connect. We currently provide two modes: Single Node Mode and Hosted Mode.

Download the repository code:

```bash
git clone https://github.com/chgaowei/AgentConnect.git
```

#### Single Node Mode

In Single Node Mode, you can complete DID authentication and encrypted communication without any third-party services.

You can run the demo code in the examples/simple_node_mode directory. First start Bob's node, then start Alice's node. Alice's node will request Bob's DID document based on Bob's DID, and establish an encrypted connection channel with Bob using the public key and message service address in the DID document to send an encrypted message. When Bob's node receives the message, it will decrypt the message and send an encrypted message back to Alice.

1. Start Bob's node
```bash
python simple_node_bob.py
```

2. Start Alice's node
```bash
python simple_node_alice.py
```

Through the logs, you can see that Alice and Bob successfully connect and perform end-to-end encrypted communication.

#### Meta-Protocol Negotiation Mode

In Meta-Protocol Negotiation Mode, Alice and Bob first negotiate a protocol, then generate processing code based on the protocol, and run the code to complete data communication. Afterwards, Alice and Bob can use the protocol code directly for data communication.

You can run the demo code in the examples/negotiation_mode directory. First start Bob's node, then start Alice's node.

1. Start Bob's node
```bash
python negotiation_bob.py
```

2. Start Alice's node
```bash
python negotiation_alice.py
```

Through the logs, you can see that Alice and Bob successfully connect and perform end-to-end encrypted communication.

## Contribution

Welcome to contribute to this project, detailed information please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License
    
This project is open-sourced under the MIT license. For more information, please see the [LICENSE](LICENSE) file.


