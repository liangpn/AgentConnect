import datetime
import os
import logging
import base64
from openai import AsyncAzureOpenAI, AzureOpenAI
from abc import ABC, abstractmethod
import openai
from pydantic import BaseModel
from typing import List, Optional

class BaseLLM(ABC):
    """Base class for LLM"""
    
    def __init__(self):
        """Initialize base class with client"""
        # TODO: This is not a good approach, needs optimization later
        self.client = None

    @abstractmethod
    async def async_generate_response(self, system_prompt: str, user_prompt: str) -> str:
        """Abstract method for async response generation, to be implemented by subclasses"""
        pass

    @abstractmethod
    async def async_generate_vision_response(self, system_prompt: str, user_prompt: str, image_path: str) -> str:
        """Abstract method for async vision response generation, to be implemented by subclasses"""
        pass

    @abstractmethod
    async def async_openai_generate_parse(self, system_prompt: str, user_prompt: str, response_format) -> BaseModel:
        """Abstract method for async parse response generation, to be implemented by subclasses"""
        pass

    @abstractmethod
    async def async_generate_vision_parse_response(self, system_prompt: str, user_prompt: str, image_path: str, response_format) -> BaseModel:
        """Abstract method for async vision parse response generation, to be implemented by subclasses"""
        pass

class AzureLLM(BaseLLM):
    """LLM subclass using Azure OpenAI"""

    def __init__(self, deployment_name: str, model_name: str):
        super().__init__()
        self.model_name = model_name
        self.deployment_name = deployment_name

        self.client = AsyncAzureOpenAI(
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            api_version="2024-02-01",
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            azure_deployment=self.deployment_name,
        )

    async def async_generate_response(self, system_prompt: str, user_prompt: str) -> str:
        """Method for async response generation"""
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
        """Method for async vision response generation"""
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
        """Method for async parse response generation"""
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
        """Method for async vision parse response generation"""
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
    """Return specific subclass instance based on input llm type"""
    if llm_type == "azure gpt4o":
        return AzureLLM(deployment_name="gpt4o", model_name="gpt-4o")
    elif llm_type == "azure gpt4o-mini":
        return AzureLLM(deployment_name="gpt4o-mini", model_name="gpt-4o-mini")
    else:
        raise ValueError(f"Unsupported LLM type: {llm_type}")
    
    
############################Test Code#################################
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
    system_prompt = "You are a helpful assistant."
    user_prompt = "Please describe the content of this image."
    image_path = "/Users/eidanlinpersonal/Desktop/personal/pic/WechatIMG27.jpeg"
    response = await llm_instance.async_generate_vision_response(system_prompt, user_prompt, image_path)
    print(f"OpenAI's understanding of the image:\n{response}\n")

async def test_async_generate_vision_parse_response():
    llm_instance = get_llm_instance("azure gpt4o-mini")
    system_prompt = "You are a helpful assistant."
    user_prompt = "Please describe the content of this image and parse its structured information."
    image_path = "/Users/eidanlinpersonal/Desktop/personal/pic/WechatIMG27.jpeg"
    response = await llm_instance.async_generate_vision_parse_response(system_prompt, user_prompt, image_path, MathReasoning)
    print(f"OpenAI's structured understanding of the image:\n{response}\n")

async def main():
    await test_async_openai_generate_parse()
    await test_async_generate_vision_response()
    await test_async_generate_vision_parse_response()

if __name__ == "__main__":
    asyncio.run(main())
