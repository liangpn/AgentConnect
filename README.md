# Agent Connect
[中文版本](README.cn.md)
## What is Agent Connect

Our vision is to provide communication capabilities for intelligent agents, allowing them to connect with each other to form a collaborative network of intelligent agents. Intelligent agents are the next generation of platforms following personal computers and mobile devices, and most current intelligent agents are designed primarily for interaction with humans. We believe that in the future, there will be billions of intelligent agents, most of which will not interact directly with humans but will collaborate with other intelligent agents to complete tasks. 

To enable communication and collaboration between intelligent agents, two major issues need to be addressed: how to perform identity verification and how to achieve encrypted communication. This is the problem our project aims to solve.

For intelligent agents, the mainstream identity authentication solutions on the current internet have two fatal flaws: they are not cross-platform and are costly. Some new technologies, such as those based on blockchain, perfectly solve the issues of centralization and cross-platform compatibility, but due to the scalability issues of blockchain technology, they are currently difficult to apply on a large scale.

We have designed a brand new **Agent Network Protocol**, based on the latest W3C DID specifications, combined with blockchain technology and end-to-end encrypted communication technology. This protocol provides a novel identity authentication and encrypted communication solution for intelligent agents, enabling them to control their own identity identifiers and perform identity authentication and encrypted communication with any other intelligent agent. Agent Connect is an open-source implementation based on the Agent Network Protocol.

For more detailed information about our solution, please visit the Agent Network Protocol GitHub page: [https://github.com/chgaowei/AgentNetworkProtocol](https://github.com/chgaowei/AgentNetworkProtocol)

Welcome to contact us to discuss the future of the intelligent agent collaborative network:
- email: chgaowei@gmail.com
- Discord: [https://discord.gg/SuXb2pzqGy](https://discord.gg/SuXb2pzqGy)  
- Official Website: [https://www.agent-network-protocol.com/](https://www.agent-network-protocol.com/)  

## Milestones
- [x] Initial version development completed, supporting single-node and hosted modes
- [ ] Support more data formats: files (images, videos, audio), live broadcasts, real-time communication (RTC), etc.
- [ ] Design and implement a meta-protocol for collaboration between intelligent agents based on the Agent Network Protocol, layer 0 protocol
- [ ] Compatible with DID web methods, W3C Verifiable Credentials (VC), supporting financial transactions between DIDs
- [ ] The core connection protocol uses binary instead of the current JSON format to improve transmission efficiency
- [ ] Rewrite AgentConnect in Rust to improve performance and support more platforms: macOS, Linux, iOS, Android
- [ ] Support more encryption algorithms
- [ ] Explore fully blockchain-based solutions

## Installation

The latest version has been removed from pypi, so you can install it directly:

```bash
pip install agent-connect
```

### Run

After installing the agent-connect library, you can run our demo to experience the powerful functions of agent-connect. We currently provide two modes: single-node mode and hosted mode.

#### Single-node mode

In single-node mode, you do not need any other third-party services to complete DID identity verification and encrypted communication.

You can run the simple_node code in the examples directory. First, start alice's node, then start bob's node. Bob's node will request alice's DID document from alice's node according to alice's DID, and establish an encrypted connection channel with alice based on the public key and message service address in the DID document. Then, bob sends an encrypted message to alice. After receiving the message, alice decrypts it and sends an encrypted message back to bob.

1. Start alice's node
```bash
python simple_node_alice.py
```

2. Start bob's node
```bash
python simple_node_bob.py
``` 

#### Hosted mode

In hosted mode, we provide a did server, which is used to host users' did documents and forward messages between different dids.

You can run the sample code in the examples directory. First, generate the did documents for alice and bob, and save alice's did document to the did server. Then, bob can connect to alice's did and perform end-to-end encrypted communication.

1. Generate two did documents alice.json and bob.json, save them to the specified files, and register them to the did server
```bash
python sample_did.py alice.json
python sample_did.py bob.json
```

2. Start alice's demo
```bash
python sample_alice.py alice.json
```

3. Start bob's demo
```bash
python sample_bob.py bob.json
```

You can see from the logs that alice and bob successfully connected and performed end-to-end encrypted communication.

## Contribution

Welcome to contribute to this project, and welcome to contact us to discuss the future of the intelligent agent collaborative network. It is best to communicate with us in the discord group before contributing to avoid duplicate work.

## License
    
This project is open source under the MIT license. For more information, please see the LICENSE file.

## Package upload (first change the version number in setup.py)

```bash
python setup.py sdist bdist_wheel 
twine upload dist/*        
```

