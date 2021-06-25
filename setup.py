from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    readme = f.read()

setup(
  name='webeye',
  version='1.0.0',
  long_description=readme,
  long_description_content_type="text/markdown",
  description='A best Powerful module for making ethical hacking tools easier',
  url='https://github.com/Zaeem20/webeye',
  author="Zaeem Technical",
  author_email='business@zaeemtechnical.ml',
  license='MIT',
  classifiers=["License :: OSI Approved :: MIT License","Programming Language :: Python :: 3.8",],
  python_requires=">=3.8",
  install_requires=['aiohttp >=3'],
  keywords="webeye red_hawk nikto webrecon recondog",
  packages=find_packages(exclude=["docs","test"]),
  data_files=None
)
