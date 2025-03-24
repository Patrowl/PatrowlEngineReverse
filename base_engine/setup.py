from setuptools import setup

setup(
    name="base_engine",
    version="0.1.1",
    description="Base engine",
    author="Patrowl",
    license="BSD 2-clause",
    packages=["base_engine"],
    install_requires=[
        "redis==5.2.1",
        "pydantic==2.10.6",
        "fastapi==0.115.12",
        "uvicorn==0.34.0",
    ],
)
