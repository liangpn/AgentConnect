# AgentConnect4Java

这是Python AgentConnect代码库的Java实现版本。它提供了DID（去中心化标识符）生成、身份验证和加密操作的功能。

## 项目结构

项目按以下包进行组织：

- `com.agentconnect.authentication`: 包含DID身份验证相关的类
- `com.agentconnect.utils`: 包含加密操作和其他辅助功能的工具类

## 构建项目

本项目使用Maven进行依赖管理。构建项目的命令：

```bash
mvn clean package
```

## 依赖项

- BouncyCastle：用于加密操作
- AsyncHttpClient：用于异步HTTP请求
- Jackson：用于JSON处理
- NovaCrypto Base58：用于Base58编码/解码
- SLF4J和Logback：用于日志记录
- JSON Canonicalization Scheme：用于JSON规范化

## 许可证

本项目基于MIT许可证开源。

## 作者

原始Python实现：GaoWei Chang (chgaowei@gmail.com)。