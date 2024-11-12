from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
import json


class Test:
    def __init__(self):
        self.a = 1

    def test(self):
        print(self.a)

t = Test()
f = t.test

f()


