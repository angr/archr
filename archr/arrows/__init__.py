import contextlib
import tempfile
import os

@contextlib.contextmanager
def bundle(arrow_name):
	bundle_path = tempfile.mktemp()
	os.system("%s/%s_bundle.sh %s" % (os.path.dirname(__file__), arrow_name, bundle_path))
	yield bundle_path
	os.unlink(bundle_path)
