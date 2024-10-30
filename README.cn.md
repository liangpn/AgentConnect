# AgentConnect

[English Version](README.md)

## AgentConnect是什么

AgentConnect是[Agent Network Protocol(ANP)](https://github.com/chgaowei/AgentNetworkProtocol)的开源实现。

## 愿景

在人工智能迅猛发展的新时代，我们正迈入智能体网络的崭新纪元。想象未来：你的个人助理智能体在为你订餐时，与餐厅的智能体无缝沟通；你的智能家居智能体与能源管理智能体协同优化用电；你的投资顾问智能体与全球市场分析智能体实时交换信息......这就是即将到来的智能体网络时代。

然而，正如比尔盖茨在[一篇博客](https://www.gatesnotes.com/AI-agents)中所说，目前还没有一个标准协议允许智能体之间相互通信。这就是Agent Network Protocol (ANP)致力于去解决的问题。

Agent Network Protocol(ANP)的愿景是**定义智能体之间的连接方式，为数十亿智能体构建一个开放、安全、高效的协作网络**。就像互联网标准协议的发展成就了近三十年的信息时代，我们相信，在不远的将来，数十亿智能体将通过ANP构建起前所未有的协作网络，创造出比现有互联网更大的价值。在AI技术和ANP加持下，智能体网络最终会演化成一个**自组织、自协商**的高效协作网络，这是一个令人无比兴奋的未来。

## 挑战

Agent Network Protocol(ANP)致力于解决连接中的三大挑战：

- 智能体之间如何进行身份认证和端到端加密通信
- 智能体之间如何进行协议协商，从而进化成一个自组织、自协商网络
- 如何对智能体网络达成的共识协议进行统一管理，从而加速智能体之间协议协商过程

## 协议架构

为了应对上面的三大挑战，Agent Network Protocol(ANP)整体上设计为三层架构，从下到上依次是身份与加密通信层、元协议层、应用协议层，如下图所示：

<p align="center">
  <img src="/images/protocol-layer-design.png" width="50%" alt="协议分层图"/>
</p>

## AgentConnect架构

AgentConnect的技术架构如下图：

<p align="center">
  <img src="/images/agent-connect-architecture.png" width="50%" alt="项目架构图"/>
</p>

对应Agent Network Protocol的三层架构，AgentConnect主要包括以下几个部分：

1. **身份认证模块与端到端加密模块**
   主要实现基于W3C DID的身份认证和端到端加密通信，包括DID文档的生成、校验、获取，以及基于DID和ECDHE(Elliptic Curve Diffie-Hellman Ephemeral，椭圆曲线迪菲-赫尔曼临时密钥交换)端到端加密通信方案实现。

2. **元协议模块**
   元协议模块需要基于LLM（大语言模型）和元协议实现，主要功能包含基于元协议的应用协议协商、协议代码实现、协议联调、协议处理等。

3. **应用层协议集成框架**
   主要的目的是管理和其他智能体通信的协议规范文档以及协议代码，包括应用协议加载、应用协议卸载、应用协议配置、应用协议处理。使用这个框架，智能体可以方便的、按需加载运行所需要的现成协议，加快智能体协议协商过程。

除了以上的功能之外，AgentConnect未来也会在性能、多平台支持等特性上发力：

- **性能**：作为一个基础的代码库，我们希望能够提供极致的性能，未来会用Rust来重写核心部分代码。
- **多平台**：现在支持mac、Linux、windows，未来将会支持移动端、浏览器。

## 联系我们

- email: chgaowei@gmail.com
- Discord: [https://discord.gg/SuXb2pzqGy](https://discord.gg/SuXb2pzqGy)  
- 官网: [https://www.agent-network-protocol.com/](https://www.agent-network-protocol.com/)  

## 里程碑

无论是协议还是开源代码实现，我们整体式是按照以下的顺序逐步的推进：

- 构建身份认证与端到端加密通信协议与实现。这是我们整个项目的基础与核心，当前协议设计和代码基本完成。
- 元协议设计与元协议代码实现。这将有助于智能体网络演进为一个自组织、自协商的高效协作网络，是我们当下正在做的事情，这将是一个令人兴奋的功能，预计不久之后我们就会发布第一个版本。
- 应用层协议集成框架开发。这将有助于Agent Network Protocol(ANP)在各种场景中为智能体提供服务。

除此之外，我们还会遵循先整体，后细节的原则。早期我们会致力于整体架构的搭建，为每一个主要的模块构建一个整体的轮廓，让它快速的运行起来，而不是构建一个个精美但无法运行的模块。

为了推动Agent Network Protocol(ANP)成为行业的标准，我们将会在合适的时间组建ANP标准化委员会，致力于推动ANP成为W3C等国际标准化组织认可的行业标准。

下面是当前AgentConnect的开发功能和进度：

- [x] 初始版本开发完成，支持单节点模式和托管模式
- [ ] 核心的连接协议使用二进制替代当前的json格式，提升传输效率
- [ ] 支持更多加的数据格式：文件（图片、视频、音频）、直播、实时通信（RTC）等
- [ ] 基于Agent Network Protocol，设计并实现智能体之间协作的元协议、layer0层协议
- [ ] 兼容DID web方法，W3C 可验证凭证（Verifiable Credentials, VC），支持DID之间进行资金交易
- [ ] 使用Rust重写AgentConnect，提升性能，支持更多平台：macOS、Linux、iOS、Android
- [ ] 支持更多的加密算法
- [ ] 探索完全基于区块链的方案

## 安装

```bash
pip install agent-connect
```

### 运行

在安装完agent-connect库后，可以运行我们的demo，体验agent-connect的强大功能。我们当前提供两种模式：单节点模式和托管模式。

#### 单节点模式

在单节点模式下，你不需要其他任何三方服务，就可以完成DID的身份验证和加密通信。

你可以运行examples目录下的simple_node代码，先启动alice的节点，再启动bob的节点，bob节点会根据alice的DID，向alice节点请求alice的DID文档，并且根据DID文档中的公钥和消息服务地址，和alice建立加密连接通道，发送一条加密消息。alice节点收到消息后，会解密消息，并且发送一条加密消息给bob。

1. 启动alice的节点
```bash
python simple_node_alice.py
```

2. 启动bob的节点
```bash
python simple_node_bob.py
``` 

#### 托管模式

在托管模式下，我们提供一个did server，用于托管用户的did文档、转发不同DID之间的消息。

你可以运行examples目录下的sample代码，先生成alice和bob的did文件，并且将alice的did文件保存到did server，然后bob可以连接alice的did，进行端到端的加密通信。

1. 生成两个did文档alice.json和bob.json，保存到指定文件中，并注册到did server
```bash
python sample_did.py alice.json
python sample_did.py bob.json
```

2. 启动alice的demo
```bash
python sample_alice.py alice.json
```

3. 启动bob的demo
```bash
python sample_bob.py bob.json
```

可以通过日志看到，alice和bob成功连接，并且进行端到端的加密通信。


## 打包上传（先更改setup.py中版本号）

```bash
python setup.py sdist bdist_wheel 
twine upload dist/*        
```

## 贡献

欢迎对本项目进行贡献，详细请参阅[CONTRIBUTING.cn.md](CONTRIBUTING.cn.md)。

## 许可证
    
本项目基于MIT许可证开源。详细信息请参阅[LICENSE](LICENSE)文件。


