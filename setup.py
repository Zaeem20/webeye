from setuptools import setup, find_packages
import re

version = ''
with open('webeye/__init__.py') as f:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', f.read(), re.MULTILINE).group(1)

if version.endswith(('a', 'b', 'rc')):
    # append version identifier based on commit count
    try:
        import subprocess
        p = subprocess.Popen(['git', 'rev-list', '--count', 'HEAD'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if out:
            version += out.decode('utf-8').strip()
        p = subprocess.Popen(['git', 'rev-parse', '--short', 'HEAD'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if out:
            version += '+g' + out.decode('utf-8').strip()
    except Exception:
        pass

with open("README.md", "r", encoding="utf-8") as f:
    readme = f.read()

setup(
    name='webeye',
    version=version,
    long_description=readme,
    long_description_content_type="text/markdown",
    entry_points={'console_scripts':['webeye=webeye.__main__:main']},
    description='A Best Powerful module for making ethical hacking tools easier',
    url='https://github.com/Zaeem20/webeye',
    author="Zaeem Technical",
    author_email='business@zaeemtechnical.ml',
    license='MIT',
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Environment :: Web Environment",
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.6"],
    python_requires=">=3.6",
    install_requires=['requests >= 2','httpx == 0.20.0'],
    keywords="webeye red_hawk nikto webrecon recondog",
    packages=find_packages(exclude=["docs","tests"]),
    data_files=None
)
