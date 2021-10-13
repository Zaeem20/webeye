from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    readme = f.read()

setup(
    name='webeye',
    version='2.1.7',
    long_description=readme,
    long_description_content_type="text/markdown",
    description='A Best Powerful module for making ethical hacking tools easier',
    url='https://github.com/Zaeem20/webeye',
    author="Zaeem Technical",
    author_email='business@zaeemtechnical.ml',
    license='MIT',
    entry_points={
        "console_scripts": [
            "webeye = webeye.cli:main"
        ]
    },
    classifiers=["License :: OSI Approved :: MIT License","Programming Language :: Python :: 3.8",],
    python_requires=">=3.8",
    install_requires=['requests >= 2','httpx == 0.19.0'],
    keywords="webeye red_hawk nikto webrecon recondog",
    packages=find_packages(exclude=["docs","tests"]),
    data_files=None
)
