from pathlib import Path
from setuptools import setup, find_packages


def read_requirements():
    req_path = Path(__file__).parent / 'requirements.txt'
    if not req_path.exists():
        return []

    requirements = []
    for line in req_path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        requirements.append(line)

    return requirements

setup(
    name='corscan',
    version='1.0.2',
    packages=find_packages(),
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'corscan=corscan.cli:main',
            'crsn=corscan.cli:main',
        ],
    },
    author='Angix Black',
    description='Advanced CORS Vulnerability Detection & Analysis Tool',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Angix-Black/Corscan',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],
    python_requires='>=3.6',
    keywords='cors security vulnerability scanner',
)

