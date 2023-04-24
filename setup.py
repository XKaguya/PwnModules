#!python
# -*- coding:utf-8 -*-
from __future__ import print_function
from setuptools import setup, find_packages
import PwnModules

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name="PwnModules",
    version=PwnModules.__version__,
    author="RedLeaves",
    author_email="rx700@vip.qq.com",
    description="A open-source Pwntools Extern Functions.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    url="",
    py_modules=['PwnModules'],
    install_requires=[
        "pwntools"
        ],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        'Programming Language :: Python :: Implementation :: CPython',
    ],
)

