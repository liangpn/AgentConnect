# Agent Connect
[English Version](README.md)
## Agent Connect是什么

我们的愿景是为智能体提供通信能力，让智能体和智能体相互连接成一个智能体协作网络。
智能体是个人电脑和移动终端之后新一代的平台，当前的智能体大部分都基于与人交互而设计的。我们认为未来会出现数十亿规模的智能体，它们大部分并不直接与人交互，而是和其他智能体一起协作完成任务。
智能体之间相互通信、协作，需要解决两大问题：如何进行身份验证，如何进行加密通信。这就是我们的项目想解决的问题。

对于智能体来说，当前互联网的主流身份认证方案存在两个致命的问题：无法跨平台、成本较高。新型的一些技术比如基于区块链的方案，虽然完美的解决了中心化和跨平台的问题，但是受限于区块链技术扩展性问题，当下难以大规模应用。

对此，我们设计了一个全新的智能体网络协议（Agent Network Protocol），基于W3C最新发布的DID规范，结合区块链技术和端到端加密通信技术，为智能体提供了一种全新的身份认证和加密通信解决方案，它能够让智能体控制自己的身份标识，并且和任意其他智能体进行身份认证和加密通信。

关于我们方案更详细的资料，请阅读：[AgentConnect技术文档](https://egp0uc2jnx.feishu.cn/wiki/BqYiwiblRiu81FkQNUfcfaIwniK?from=from_copylink)

欢迎和我们联系，一起探讨智能体协作网络的未来：
- email: chgaowei@gmail.com
- Discord: [https://discord.gg/CDYdTPXXMB](https://discord.gg/CDYdTPXXMB)  
- Official Website: [https://pi-unlimited.com](https://pi-unlimited.com)  

## 里程碑

- [x] 初始版本开发完成，支持单节点模式和托管模式
- [ ] 支持更多加的消息格式：文件（图片、视频、音频）、直播、实时通信（RTC）、资金交易等
- [ ] 核心的连接协议使用二进制替代当前的json格式，提升传输效率
- [ ] 使用Rust重写AgentConnect，提升性能，支持更多平台：macOS、Linux、iOS、Android
- [ ] 支持更多的加密算法
- [ ] 探索完全基于区块链的方案

## 安装

最新版本已删除pypi，直接安装即可：

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

## 贡献

欢迎对本项目进行贡献，也欢迎和我们联系，一起探讨智能体协作网络的未来。在贡献之前最好现在discord群组中和我们沟通，避免重复工作。

## 许可证
    
本项目基于MIT许可证开源。详细信息请参阅LICENSE文件。

## 打包上传（先更改setup.py中版本号）

```bash
python setup.py sdist bdist_wheel 
twine upload dist/*        
```

