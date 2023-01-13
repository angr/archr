import contextlib
import subprocess
import tempfile
import shutil
import os


@contextlib.contextmanager
def bundle(implant_name: str):
    bundle_path = tempfile.mkdtemp(prefix="archr_bundle_")

    bundle_base_dir = os.path.dirname(__file__)
    if os.path.exists(os.path.join(bundle_base_dir, implant_name)):
        subprocess.check_call([f"{bundle_base_dir}/{implant_name}/bundle", bundle_path])
    else:
        subprocess.check_call([f"{bundle_base_dir}/{implant_name}_bundle", bundle_path])

    yield bundle_path

    shutil.rmtree(bundle_path)


@contextlib.contextmanager
def bundle_binary(path: str):
    bundle_path = tempfile.mkdtemp(prefix="archr_bundle_binary_")

    bundle_base_dir = os.path.dirname(__file__)
    subprocess.check_call([f"{bundle_base_dir}/GENERIC/bundle", bundle_path, path])
    yield bundle_path

    shutil.rmtree(bundle_path)
