from setuptools import setup

setup(
    name='corscan',
    version='1.0.0',
    py_modules=['corscan'],
    install_requires=[
        'requests',
        'colorama',
    ],
    entry_points={
        'console_scripts': [
            'corscan=corscan:main',
            'crsn=corscan:main',
        ],
    },
    author='Angix Black',
    description='Advanced CORS Header Checker Tool with Vulnerability Detection and Bypass Attempts',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Angix-Black/Corscan',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
