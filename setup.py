from setuptools import setup, find_packages

setup(
    name="b4pass",
    version="0.1",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "b4pass=b4pass:main",
        ],
    },
)
