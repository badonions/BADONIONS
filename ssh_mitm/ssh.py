import paramiko
import socket
import socks
import stem.process
from stem.util import term
from gevent import Timeout
from Queue import Queue
import traceback
import threading
import random
import sys
import signal
import shutil

"""
require:
    gevent stem paramiko socks
todo:
    * CTRL-c handler & cleanup
    * auto-fetch key
"""

def getaddrinfo(*args):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]

class Log:
    LOG_SUCCESS = 0
    LOG_ERROR = 1
    LOG_INFO = 2
    LOG_WARN = 3

    # only show success or error
    level = 1

    loglevels = {
        LOG_SUCCESS: term.Color.GREEN,
        LOG_ERROR: term.Color.RED,
        LOG_INFO: '',
        LOG_WARN: ''
    }

    def __init__(self, msg, LOG_LEVEL = LOG_INFO):
        if LOG_LEVEL > self.level:
            return

        #print self.loglevels[LOG_LEVEL], msg
        print term.format(msg, self.loglevels[LOG_LEVEL])

class TorNodeCheck(threading.Thread):
    def __init__(self, host, port, queue, timeout = 10):
        self.host = host
        self.port = port
        self.queue = queue
        self.timeout = timeout

        threading.Thread.__init__(self)

    def log(self, msg, level = Log.LOG_INFO):
        exit_node = self.config['ExitNodes']
        Log('\r[%s] %s' % (exit_node, msg), level)

    def run(self):
        while True:
            config = self.queue.get()

            config['DataDirectory'] = '/tmp/tor_data_%s' % (config['SocksPort'])
            self.config = config

            self.log('connecting...')

            opened = False
            with Timeout(self.timeout, False):
                self.tor_process = stem.process.launch_tor_with_config(config=self.config, timeout=None)
                self.tor_process.stdout.close()
                opened = True

            if not opened:
                self.log('connection failed', Log.LOG_ERROR)
                return self.cleanup()

            self.log('connected!')

            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', int(self.config['SocksPort']))
            socket.socket = socks.socksocket

            socket.getaddrinfo = getaddrinfo
            socket.setdefaulttimeout(self.timeout)

            self.check()
            self.cleanup()

    def check(self):
        return False

    def cleanup(self):
        self.tor_process.terminate()
        try:
            shutil.rmtree(self.config['DataDirectory'])
        except:
            pass

        self.queue.task_done()

class SSHCheck(TorNodeCheck):
    def __init__(self, host, port, queue, timeout = 10, server_key = None):
        self.server_key = server_key
        super(SSHCheck, self).__init__(host, port, queue)

    def check(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
        except Exception as e:
            self.log(e, Log.LOG_ERROR)
            return False

        try:
            t = paramiko.Transport(sock)
            t.start_client()
            key = t.get_remote_server_key()
            t.close()

            k = key.get_base64()
            if k == self.server_key:
                self.log('OK fingerprint', Log.LOG_SUCCESS)
            else:
                self.log('MITM! Fingerprint:\n%s' % (k), Log.LOG_ERROR)
                return True
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.log(e, Log.LOG_ERROR)
            return False

def signal_handler(signal, frame):
    print '- CTRL-C, exit!'
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

### MAIN

SOCKS_PORT, CONTROL_PORT = 44100, 44200
NUM_THREADS = 10

# put your host,port and *base64* fingerprint here
host, port = '188.166.11.125', 22
server_key = '''
QUFBQUIzTnphQzF5YzJFQUFBQURBUUFCQUFBQkFRQytqUEhuN3JpT3c2b2ZRa283Z0ZkOWs2T0xZ
RCsvWEhId2gzeDRQUDZmOVQ1N3p0UVhXemowcEZnaUFJWlhNRVlxRzhDb291T3VyRmlhU3c1YlJr
Y29vb3FnbjJFK2FLRXFqdlNwTWxyeHJvQVBoYjg1WjJqZjZ6czR5RDdkam1EdXZKWXRqM0d0Z2Rv
MXN1bmpzejM5NXlSTWQxeWRqbG9yWStacjlYcWNtZkV3NXB4ejhidFRVWHFiRWtUSk1EN3RENzh4
T2ZtblhBQTh0S3VSUjJwcXRUazZmUDc1MFZqN2RVUWllRmlIS1hucVJvblcvN0ZURzFGVU1adEhw
c2dLUHN2N1lhajJrUXMvdm52YiszRDJwdnk1YnBHa1JyT0hMVkw0Z21uUXBMUFpTWXBDd1ViWGFX
QVFkaS9yYUF3eldSYTRlckZlSXMyU3RicE5ReTBGCg==
'''.strip()

# more verbose output
Log.level = 4

q = Queue(maxsize=0)

fps = open('fp.txt').read().split('\n')[:-1]
fps = fps #[:10]
i = 0
threads = []
for tid in xrange(NUM_THREADS):
    t = SSHCheck(host, port, q, server_key=server_key)
    t.setDaemon(True)
    t.start()
    threads.append(t)

for i, exit_node in enumerate(fps[:20]):
    exit_node = random.choice(fps)
    config = {
        'SocksPort': str(SOCKS_PORT+i),
        'ControlPort': str(CONTROL_PORT+i),
        'ExitNodes': exit_node
    }

    q.put(config)

q.join()
