from setuptools import setup, find_packages

setup(
    name="b4pass",
    version="0.2",
    packages=find_packages(),
    py_modules=["b4pass"],
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "b4pass=b4pass:main",
        ],
    },
)
