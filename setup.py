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
    version='9.0.9438',
    python_requires='>=3.6',
    packages=packages,
    package_data = {
        'archr': ['implants/*.sh', 'implants/*/*']
    },
    install_requires=[
        'shellphish_qemu>=0.12.2',
        'pygdbmi',
        'docker',
        'nclib>=1.0.0rc3',
        'patchelf-wrapper',
        'cle==9.0.9438'
    ],
    extras_require = {
        'angr':  ["angr==9.0.9438"],
        'qtrace': ["qtrace"],
    },
    description='Target-centric program analysis.',
    url='https://github.com/angr/archr',
    classifiers=["Operating System :: POSIX :: Linux"],
)
