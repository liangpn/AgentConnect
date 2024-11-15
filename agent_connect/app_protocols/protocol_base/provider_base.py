# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


# provider base class

# Common interfaces for provider:
# 1. Send callback function
# 2. Receive data interface (non-async, using async event internally)

# 怎么设计provider的回调？
# 一类是直接回调获取数据，一类是回调事件与数据。回调有输入输出
# 如果说不能实现用AI生成代码处理全流程，那么协议协商就没有意义了。
# demo上，实现一个简单的provider，使用回调函数直接获取数据。协议处理部分代码，数据获取部分代码，使用AI生成。
# 也实现一个requester，通过生成的逻辑代码，直接调用获取provider的数据。
# 要为demo想一个好的、有用的场景，两端都使用AI生成协议代码、业务逻辑代码。
# 自己生成自己的代码，是否可以作为一个新的项目。

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Awaitable

class ProviderBase(ABC):
    """Base class for protocol providers"""
    
    def __init__(self):
        self._send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
        
    def set_send_callback(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Set async callback function for sending binary messages
        
        Args:
            callback: Async function that takes binary data (bytes) as input and sends 
                     it through the transport layer. The function should be a coroutine
                     and handle the actual sending mechanism and any potential errors.
                     Returns Awaitable.
        """
        self._send_callback = callback

    def set_protocol_callback(self, callback: Callable[[dict], Awaitable[None]]) -> None:
        pass
    
    @abstractmethod
    async def handle_message(self, message: bytes) -> None:
        """Handle received message
        
        Args:
            message: Received binary message data
        """
        pass










