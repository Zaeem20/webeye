from setuptools import setup, find_packages
import os

def read(rel_path: str) -> str:
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, rel_path)) as fp:
        return fp.read()


def get_version(rel_path: str) -> str:
    for line in read(rel_path).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")


with open("README.md", "r", encoding="utf-8") as f:
    readme = f.read()

setup(
    name='webeye',
    version=get_version('webeye/__init__.py'),
    long_description=readme,
    long_description_content_type="text/markdown",
    entry_points={'console_scripts':['webeye=core.cli:main']},
    description='A Best Powerful module for making ethical hacking tools easier',
    url='https://github.com/Zaeem20/webeye',
    author="Zaeem Technical",
    author_email='business@zaeemtechnical.ml',
    license='MIT',
    classifiers=["License :: OSI Approved :: MIT License","Programming Language :: Python :: 3.8",],
    python_requires=">=3.8",
    install_requires=['requests >= 2','httpx == 0.19.0'],
    keywords="webeye red_hawk nikto webrecon recondog",
    packages=find_packages(exclude=["docs","tests"]),
    data_files=None
)
