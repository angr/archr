import contextlib
import subprocess
import tempfile
import logging
import signal
import time
import re
import io
import os

l = logging.getLogger("archr.bows.qemu_tracer")

from .. import arrows
from . import Bow

class TraceResults:
	process = None
	socket = None

	# results
	returncode = None
	signal = None
	crashed = None
	timed_out = None

	# introspection
	trace = None
	crash_address = None
	base_address = None
	magic_contents = None
	core_path = None

	# internal stuff
	_trace_file = None
	_magic_file = None

_trace_re = re.compile(br'Trace (.*) \[(?P<addr>.*)\].*')

class QEMUTracerBow(Bow):
	def nock(self):
		with arrows.bundle("shellphish_qemu") as b:
			self.target.inject_tarball("/tmp/shellphish_qemu", tarball_path=b)

	def fire(self, *args, testcase=(), **kwargs): #pylint:disable=arguments-differ
		if type(testcase) in [ str, bytes ]:
			testcase = [ testcase ]

		with self.fire_context(*args, **kwargs) as r:
			for t in testcase:
				r.process.stdin.write(t.encode('utf-8') if type(t) is str else t)
				time.sleep(0.01)
			r.process.stdin.close()

		return r

	@contextlib.contextmanager
	def fire_context(self, timeout=10, record_trace=True, record_magic=False, save_core=False, **kwargs):
		assert self.target.target_path.startswith("/"), "The qemu tracer currently chdirs into a temporary directory, and cannot handle relative argv[0] paths."

		tmp_prefix = tempfile.mktemp(dir="/tmp/", prefix="tracer-")
		target_trace_filename = tmp_prefix + ".trace" if record_trace else None
		target_magic_filename = tmp_prefix + ".magic" if record_magic else None
		target_tempdir = tempfile.mkdtemp(prefix="tracer")
		local_core_filename = tmp_prefix + ".core" if save_core else None

		target_cmd = self._build_command(target_tempdir, trace_filename=target_trace_filename, magic_filename=target_magic_filename, **kwargs)

		with contextlib.ExitStack() as exit_stack:
			r = TraceResults()

			# add retrievers for important files
			if target_trace_filename:
				r._trace_file = exit_stack.enter_context(self.target.retrieval_context(target_trace_filename, io.BytesIO()))
			if target_magic_filename:
				r._magic_file = exit_stack.enter_context(self.target.retrieval_context(target_magic_filename, io.BytesIO()))
			if local_core_filename:
				target_core_glob = os.path.join(target_tempdir, "qemu_*.core")
				r.core_path = exit_stack.enter_context(self.target.retrieval_context(target_core_glob, local_core_filename, glob=True))

			r.process = exit_stack.enter_context(self.target.run_context(target_cmd, timeout=timeout))

			try:
				yield r
				r.timed_out = False
			except subprocess.TimeoutExpired:
				r.timed_out = True

		if not r.timed_out:
			r.returncode = r.process.returncode

			# did a crash occur?
			if r.returncode in [ 139, -11 ]:
				r.crashed = True
				r.signal = signal.SIGSEGV
			elif r.returncode == [ 132, -9 ]:
				r.crashed = True
				r.signal = signal.SIGILL

		if record_trace:
			r._trace_file.seek(0)
			# Find where qemu loaded the binary. Primarily for PIE
			r.base_address = int(next(t.split()[1] for t in r._trace_file if t.startswith(b"start_code")), 16) #pylint:disable=stop-iteration-return

			# record the trace
			r.trace = [
				int(_trace_re.match(t).group('addr'), 16) for t in r._trace_file if t.startswith(b"Trace ") #pylint:disable=not-an-iterable
			]

			# grab the faulting address
			if r.crashed:
				r.crash_address = r.trace[-1]

			l.debug("Trace consists of %d basic blocks", len(r.trace))

		if record_magic:
			r._magic_file.seek(0)
			r.magic_contents = r._magic_file.read()
			assert len(r.magic_contents) == 0x1000, "Magic content read from QEMU improper size, should be a page in length"

	@property
	def qemu_variant(self):
		return "shellphish-qemu-linux-x86_64"

	def _build_command(self, tempdir, trace_filename=None, library_path=None, magic_filename=None, report_bad_args=False, seed=None):
		"""
		Here, we build the tracing command.
		"""

		#
		# First, the arrow invocation
		#

		cmd_args = [ "/tmp/shellphish_qemu/fire", tempdir, self.qemu_variant ]

		#
		# Next, we build QEMU options.
		#

		# hardcode an argv[0]
		#cmd_args += [ "-0", program_args[0] ]

		# record trace
		if trace_filename:
			cmd_args += ["-d", "exec", "-D", trace_filename]
		else:
			cmd_args += ["-enable_double_empty_exiting"]

		# save CGC magic page
		if magic_filename:
			cmd_args += ["-magicdump", magic_filename]
		else:
			magic_filename = None

		if seed is not None:
			cmd_args.append("-seed")
			cmd_args.append(str(seed))

		if report_bad_args:
			cmd_args += ["-report_bad_args"]

		# Memory limit option is only available in shellphish-qemu-cgc-*
		if 'cgc' in self.qemu_variant:
			cmd_args += ["-m", "8G"]

		if 'cgc' not in self.qemu_variant:
			l.warning("setting LD_BIND_NOW=1. This will have an effect on the environment.")
			cmd_args += ['-E', 'LD_BIND_NOW=1']

		if library_path:
			l.warning("setting LD_LIBRARY_PATH. This will have an effect on the environment. Consider using --library-path instead")
			cmd_args += ['-E', 'LD_LIBRARY_PATH=' + library_path]

		#
		# Now, we add the program arguments.
		#

		cmd_args += self.target.target_args

		return cmd_args
