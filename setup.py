# pylint: disable=missing-class-docstring
import glob
import os
import platform
import shutil
import subprocess
import sys
import pathlib
from distutils.command.build import build as st_build
from distutils.util import get_platform

import pkg_resources
from setuptools import Command, setup
from setuptools.command.develop import develop as st_develop
from setuptools.errors import LibError

def _build_support_libraries():
    env = os.environ.copy()
    env["CMAKE_GENERATOR"] = "Ninja"

    curr_dir = pathlib.Path(__file__).parent.absolute()
    tcp_udp_dir = os.path.join(curr_dir, "archr", "implants", "udp_tcp_convert")
    subprocess.run(["cmake", ".", "-Bbuild"], cwd=tcp_udp_dir, env=env, check=True)

    build_dir = os.path.join(tcp_udp_dir, "build")
    subprocess.run(["ninja"], cwd=build_dir, env=env, check=True)

    shutil.copy(os.path.join(build_dir, "lib", "libudp_to_tcp.so"), tcp_udp_dir)


def _clean_support_libraries():
    curr_dir = pathlib.Path(__file__).parent.absolute()
    build_dir = os.path.join(curr_dir, "archr", "implants", "udp_tcp_convert", "build")
    shutil.rmtree(build_dir, ignore_errors=True)

class build(st_build):
    def run(self, *args):
        self.execute(_build_support_libraries, (), msg="Building Archr support libraries")
        super().run(*args)


class clean_native(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.execute(_clean_support_libraries, (), msg="Cleaning up build directories")


cmdclass = {
    "build": build,
    "clean_native": clean_native,
}

if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    sys.argv.append('--plat-name')
    name = get_platform()
    if 'linux' in name:
        sys.argv.append('manylinux2014_' + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace('.', '_').replace('-', '_'))

setup(cmdclass=cmdclass)
