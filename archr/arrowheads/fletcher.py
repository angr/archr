import sys
import os
import fcntl
import selectors
import socket
import time

from . import Arrowhead


class Fletcher:
    def __init__(self, proc):
        self.trace = list()
        self._proc = proc


    def run(self):
        self._selector = selectors.DefaultSelector()
        self._register(sys.stdin.buffer.raw, self._read_stdin)
        self._register(self._proc.stdout, self._read_proc_stdout)
        self._register(self._proc.stderr, self._read_proc_stderr)

        return_code = None

        try:
            while self._selector.get_map():
                return_code = self._run_return_code()
                if return_code != None:
                    break
                for key, mask in self._selector.select():
                    callback = key.data
                    fileobj = key.fileobj
                    if type(fileobj) is socket.socket:
                        data = fileobj.recv(65535)
                    else:
                        data = fileobj.read()
                    if not data:
                        self._unregister(fileobj)
                    callback(data)

        except KeyboardInterrupt:
            pass

        for key in list(self._selector.get_map().values()):
            fileobj = key.fileobj
            self._unregister(fileobj)

        self._proc.terminate()

        return return_code


    def _register(self, fd, fn):
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        self._selector.register(fd, selectors.EVENT_READ, fn)


    def _unregister(self, fd):
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        self._selector.unregister(fd)


    def _output(self, data, stderr=False):
        if not stderr:
            stream = sys.stdout.buffer.raw
        else:
            stream = sys.stderr.buffer.raw

        fl = fcntl.fcntl(stream, fcntl.F_GETFL)
        fcntl.fcntl(stream, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        stream.write(data)
        stream.flush()
        fcntl.fcntl(stream, fcntl.F_SETFL, fl)


    def _read_stdin(self, data):
        self.trace.append({
            'time': time.time(),
            'data': data,
            'channel': 'stdin',
        })

        if not data:
            self._proc.stdin.close()
            return

        self._proc.stdin.write(data)
        self._proc.stdin.flush()


    def _read_proc_stdout(self, data):
        self.trace.append({
            'time': time.time(),
            'data': data,
            'channel': 'stdout',
        })

        if data:
            self._output(data)
        else:
            self._proc.terminate()


    def _read_proc_stderr(self, data):
        self.trace.append({
            'time': time.time(),
            'data': data,
            'channel': 'stderr',
        })

        if data:
            self._output(data, stderr=True)
        else:
            self._proc.terminate()



    def _run_return_code(self):
        return_code = self._proc.poll()
        return return_code


class ArrowheadFletcher(Arrowhead):
    """
    An arrowhead fletcher will allow a user to create an arrowhead by logging interactions that are performed when
    running the target program.

    :param channel_map:  A mapping from user channels to target channels: {str user_channel, str target_channel)
    """

    def __init__(self, channel_map):
        # TODO: use this channel_map, for now we are just going to map stdin/stdout
        self.channel_map = channel_map


    def run(self, flight):
        fletcher = Fletcher(flight.process)
        fletcher.run()
        trace = fletcher.trace


        import json
        print(trace)
        print(json.dumps([{k: v.decode('latin') if type(v) is bytes else v for k, v in e.items()} for e in trace], indent=4))

        return trace
