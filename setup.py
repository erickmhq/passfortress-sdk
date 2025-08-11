from setuptools import setup, find_packages

setup(
    name='passfortress-sdk',
    version='1.1.0',
    packages=find_packages(),
    install_requires=[
        'requests==2.32.3'
    ],
    python_requires='>=3.8',
)
