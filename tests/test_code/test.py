from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
import json

# 定义 DegreeEnum 枚举
class DegreeEnum(str, Enum):
    bachelor = "Bachelor"
    master = "Master"
    doctorate = "Doctorate"

# 定义 EducationExperience 模型并添加字段说明
class EducationExperience(BaseModel):
    institution: Optional[str] = Field(None, description="The name of the educational institution")
    major: Optional[str] = Field(None, description="The major or field of study")
    degree: Optional[DegreeEnum] = Field(None, description="The degree obtained (e.g., Bachelor, Master, Doctorate)")
    achievements: Optional[str] = Field(None, description="Notable achievements during the education")
    start_date: Optional[str] = Field(None, description="The start date of the education in YYYY-MM-DD format")
    end_date: Optional[str] = Field(None, description="The end date of the education in YYYY-MM-DD format")

# 生成 JSON Schema
schema = EducationExperience.schema()
print(json.dumps(schema, indent=4))
