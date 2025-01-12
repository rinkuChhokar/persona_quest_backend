from utils.handle_object_id import PyObjectId
from pydantic import BaseModel,EmailStr, Field
from typing import Optional
from bson import ObjectId


# Schema for user model
class UserLoginModel(BaseModel):
    # id: Optional[PyObjectId] = Field(default=None, alias = "_id")
    email: EmailStr
    password: str

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
