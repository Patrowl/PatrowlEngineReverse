from pydantic import BaseModel
from base_engine.base_engine import BaseOptions


class Options(BaseOptions):
    example_option: bool = False


class Metadatas(BaseModel):
    name: str
    description: str
