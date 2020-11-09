import contextlib
import tempfile
import shutil
import os

@contextlib.contextmanager
def bundle(implant_name):
    bundle_path = tempfile.mkdtemp(prefix="archr_bundle_")

    bundle_base_dir = os.path.dirname(__file__)
    if os.path.exists(os.path.join(bundle_base_dir, implant_name)):
        os.system("%s/%s/bundle %s" % (bundle_base_dir, implant_name, bundle_path))
    else:
        os.system("%s/%s_bundle %s" % (bundle_base_dir, implant_name, bundle_path))
    yield bundle_path

    shutil.rmtree(bundle_path)

@contextlib.contextmanager
def bundle_binary(path):
    bundle_path = tempfile.mkdtemp(prefix="archr_bundle_binary_")

    bundle_base_dir = os.path.dirname(__file__)
    os.system("%s/GENERIC/bundle %s %s" % (bundle_base_dir, bundle_path, path))
    yield bundle_path

    shutil.rmtree(bundle_path)
