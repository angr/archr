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
    version='8.18.10.5',
    python_requires='>=3.5',
    packages=packages,
    package_data = {
        'archr': ['arrows/*.sh', 'arrows/*/*']
    },
    install_requires=[
        'shellphish_qemu',
        'pygdbmi',
        'angr',
        'docker',
        'nclib==0.8.4rc2',
    ],
    description='Target-centric program analysis.',
    url='https://github.com/angr/archr',
)
