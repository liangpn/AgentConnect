import datetime
import os
import logging
import base64
from openai import AsyncAzureOpenAI, AzureOpenAI
from abc import ABC, abstractmethod
import openai
from pydantic import BaseModel
from typing import List

class BaseLLM(ABC):
    """LLM的基类"""

    @abstractmethod
    async def async_generate_response(self, system_prompt: str, user_prompt: str) -> str:
        """异步生成响应的抽象方法，子类需要实现"""
        pass

    @abstractmethod
    async def async_generate_vision_response(self, system_prompt: str, user_prompt: str, image_path: str) -> str:
        """异步生成视觉响应的抽象方法，子类需要实现"""
        pass

    @abstractmethod
    async def async_openai_generate_parse(self, system_prompt: str, user_prompt: str, response_format) -> BaseModel:
        """异步生成解析响应的抽象方法，子类需要实现"""
        pass

    @abstractmethod
    async def async_generate_vision_parse_response(self, system_prompt: str, user_prompt: str, image_path: str, response_format) -> BaseModel:
        """异步生成视觉解析响应的抽象方法，子类需要实现"""
        pass

class AzureLLM(BaseLLM):
    """使用Azure的OpenAI的LLM子类"""

    def __init__(self, deployment_name: str, model_name: str):
        self.model_name = model_name
        self.deployment_name = deployment_name

        self.client = AsyncAzureOpenAI(
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            api_version="2024-02-01",
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            azure_deployment=self.deployment_name,
        )

    async def async_generate_response(self, system_prompt: str, user_prompt: str) -> str:
        """异步生成响应的方法"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"Failed to generate response: {str(e)}")
            return ""

    async def async_generate_vision_response(self, system_prompt: str, user_prompt: str, image_path: str) -> str:
        """异步生成视觉响应的方法"""
        try:
            with open(image_path, "rb") as image_file:
                base64_image = base64.b64encode(image_file.read()).decode('utf-8')
            
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": user_prompt
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{base64_image}"
                                }
                            }
                        ]
                    }
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"Failed to generate vision response: {str(e)}")
            return ""
        
    async def async_openai_generate_parse(self, system_prompt: str, user_prompt: str, response_format):
        """异步生成解析响应的方法"""
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
            completion = await self.client.beta.chat.completions.parse(
                model=self.model_name,
                messages=messages,
                response_format=response_format,
            )
            return completion.choices[0].message.parsed
        except Exception as e:
            logging.error(f"Failed to generate parse response: {str(e)}")
            # Handle edge cases
            if type(e) == openai.LengthFinishReasonError:
                logging.error(f"Too many tokens: {str(e)}")
            else:
                # Handle other exceptions
                logging.error(f"Failed to generate parse response: {str(e)}")
            return None
    async def async_generate_vision_parse_response(self, system_prompt: str, user_prompt: str, image_path: str, response_format) -> BaseModel:
        """异步生成视觉解析响应的方法"""
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": user_prompt
                        }
                    ]
                }
            ]
            
            if image_path and os.path.exists(image_path):
                with open(image_path, "rb") as image_file:
                    base64_image = base64.b64encode(image_file.read()).decode('utf-8')
                messages[1]["content"].append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/jpeg;base64,{base64_image}"
                    }
                })
            start_time = datetime.datetime.now()
            completion = await self.client.beta.chat.completions.parse(
                model=self.model_name,
                messages=messages,
                response_format=response_format,
            )
            end_time = datetime.datetime.now()
            logging.info(f"openai vision parse response cost time: {end_time - start_time}")
            return completion.choices[0].message.parsed
        except Exception as e:
            logging.error(f"Failed to generate vision parse response: {str(e)}")
            return None

def get_llm_instance(llm_type: str) -> BaseLLM:
    """根据输入的llm类型返回特定的子类实例"""
    if llm_type == "azure gpt4o":
        return AzureLLM(deployment_name="gpt4o", model_name="gpt-4o")
    elif llm_type == "azure gpt4o-mini":
        return AzureLLM(deployment_name="gpt4o-mini", model_name="gpt-4o-mini")
    else:
        raise ValueError(f"Unsupported LLM type: {llm_type}")
    
    
############################测试代码#################################
import asyncio
from pydantic import BaseModel

class Step(BaseModel):
    explanation: str
    output: str

class MathReasoning(BaseModel):
    steps: List[Step]
    final_answer: str

async def test_async_openai_generate_parse():
    azure_llm = AzureLLM(deployment_name="gpt4o", model_name="gpt-4o")
    response = await azure_llm.async_openai_generate_parse(
        "You are a helpful math tutor. Guide the user through the solution step by step.",
        "how can I solve 8x + 7 = -23",
        MathReasoning
    )
    print(f"Response: {response}")
    assert response is not None
    assert isinstance(response, MathReasoning)

async def test_async_generate_vision_response():
    llm_instance = get_llm_instance("azure gpt4o-mini")
    system_prompt = "你是一个有帮助的助手。"
    user_prompt = "请描述这张图片的内容。"
    image_path = "/Users/eidanlinpersonal/Desktop/personal/pic/WechatIMG27.jpeg"
    response = await llm_instance.async_generate_vision_response(system_prompt, user_prompt, image_path)
    print(f"OpenAI对图片的理解:\n{response}\n")

async def test_async_generate_vision_parse_response():
    llm_instance = get_llm_instance("azure gpt4o-mini")
    system_prompt = "你是一个有帮助的助手。"
    user_prompt = "请描述这张图片的内容，并解析其中的结构化信息。"
    image_path = "/Users/eidanlinpersonal/Desktop/personal/pic/WechatIMG27.jpeg"
    response = await llm_instance.async_generate_vision_parse_response(system_prompt, user_prompt, image_path, MathReasoning)
    print(f"OpenAI对图片的结构化理解:\n{response}\n")

async def main():
    await test_async_openai_generate_parse()
    await test_async_generate_vision_response()
    await test_async_generate_vision_parse_response()

if __name__ == "__main__":
    asyncio.run(main())
