import io
import os
import re

from setuptools import find_packages
from setuptools import setup


def read(filename):
    filename = os.path.join(os.path.dirname(__file__), filename)
    text_type = type(u"")
    with io.open(filename, mode="r", encoding='utf-8') as fd:
        return re.sub(text_type(r':[a-z]+:`~?(.*?)`'), text_type(r'``\1``'), fd.read())

with open('./requirements.txt', 'r', encoding='utf-8') as fin:
    requires_list = [line.strip() for line in fin if line and line.strip()]

setup(
    name="fastapi_microsoft_identity",
    version="0.1.4",
    url="https://github.com/425Show/fastapi_microsoft_identity",
    license='MIT',

    author="Christos Matskas",
    author_email="christos.matskas@microsoft.com",

    description="Azure AD authentication for Fast API",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",

    packages=find_packages(exclude=('tests',)),

    install_requires=requires_list,

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10'
    ],
)
