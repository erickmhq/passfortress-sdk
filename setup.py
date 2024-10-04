from setuptools import setup, find_packages

setup(
    name='passfortress-sdk',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests==2.32.3'
    ],
    python_requires='>=3.8',
)
