from setuptools import setup

setup(
    name="base_engine",
    version="0.1.1",
    description="Base engine",
    author="Patrowl",
    license="BSD 2-clause",
    packages=["base_engine"],
    install_requires=[
        "pika==1.3.2",
        "pydantic==2.10.6",
    ],
)
