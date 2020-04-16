try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

if bytes is str:
    raise Exception("This module is designed for python 3 only.")

setup(
    name='archr',
    version='8.20.9.1',
    python_requires='>=3.5',
    packages=packages,
    package_data = {
        'archr': ['arrows/*.sh', 'arrows/*/*']
    },
    install_requires=[
        'shellphish_qemu',
        'pygdbmi',
        'docker',
        'nclib>=1.0.0rc3',
        'patchelf-wrapper',
        'cle'
    ],
    extras_require = {
        'angr':  ["angr"]
    },
    description='Target-centric program analysis.',
    url='https://github.com/angr/archr',
)
