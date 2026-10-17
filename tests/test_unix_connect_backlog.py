"""Unix listen-queue backpressure must yield to connection deadlines (PR #258)."""
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from include import MEMTIER_BINARY, TLS_CERT, TLS_KEY


class BackloggedPeer:
    def __init__(self, path, release_after=None, tls=False):
        self.path = path
        self.tls_context = None
        if tls:
            self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_context.load_cert_chain(TLS_CERT, TLS_KEY or None)
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.sockets = []
        self.threads = []
        # Linux permits backlog+1 queued connects. Fill both before memtier
        # starts, so EAGAIN does not depend on the test machine's scheduling.
        for _ in range(2):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(path)
            self.sockets.append(sock)
        if release_after is not None:
            thread = threading.Thread(target=self.accept, args=(release_after,))
            self.threads.append(thread)
            thread.start()

    def accept(self, delay):
        if self.stop.wait(delay):
            return
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.sockets.append(conn)
            thread = threading.Thread(target=self.respond, args=(conn,))
            self.threads.append(thread)
            thread.start()

    def respond(self, conn):
        conn.settimeout(0.2)
        try:
            if self.tls_context is not None:
                conn = self.tls_context.wrap_socket(conn, server_side=True)
            with conn.makefile('rb') as stream:
                while not self.stop.is_set():
                    line = stream.readline()
                    if not line:
                        break
                    args = []
                    for _ in range(int(line[1:])):
                        size = int(stream.readline()[1:])
                        args.append(stream.read(size))
                        stream.read(2)
                    conn.sendall(b'+OK\r\n' if args[0] in (b'AUTH', b'SET') else b'$-1\r\n')
        except (OSError, ValueError):
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        # Join accept before inspecting the final list of worker sockets.
        if self.threads:
            self.threads[0].join(timeout=2)
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            thread.join(timeout=2)


def run_case(env, mode):
    if sys.platform != 'linux':
        env.skip()  # Deterministic backlog+1/EAGAIN behavior is Linux-specific.
    with tempfile.TemporaryDirectory(prefix='memtier-unix-backlog-') as tmp:
        path = os.path.join(tmp, 'server.sock')
        output = os.path.join(tmp, 'result.json')
        tls = getattr(env, 'useTLS', False)
        peer = BackloggedPeer(path, 0.4 if mode == 'recover' else None, tls)
        args = [MEMTIER_BINARY, '-S', path, '-a', 'dummy-test-password',
                '-t', '1', '-c', '4' if mode == 'recover' else '1',
                '-n', '10', '--ratio=1:0', '--hide-histogram', '--json-out-file', output]
        if tls:
            args += ['--tls', '--tls-skip-verify']
        if mode == 'timeout':
            args += ['--connection-timeout=1']
        elif mode == 'stage':
            args += ['--connection-stage-timeout=1']
        elif mode == 'recover':
            args += ['--connection-timeout=2']
        proc = None
        started = time.monotonic()
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if mode == 'interrupt':
                time.sleep(0.3)
                proc.send_signal(signal.SIGINT)
            stdout, stderr = proc.communicate(timeout=8)
            stderr = stderr.decode(errors='replace')
            env.assertLess(time.monotonic() - started, 7, message=stderr)
            if mode == 'recover':
                env.assertEqual(proc.returncode, 0, message=stderr)
                with open(output) as stream:
                    result = json.load(stream)
                env.assertEqual(result['ALL STATS']['Sets']['Count'], 40)
                env.assertNotContains('Connection timeout', stderr)
            elif mode == 'timeout':
                env.assertEqual(proc.returncode, 1, message=stderr)
                env.assertContains('Connection timeout after 1 seconds', stderr)
                with open(output) as stream:
                    result = json.load(stream)
                # A pending SSL handshake must also stay idle while the
                # listener queue is full; a live write event busy-spins here.
                env.assertLess(result['ALL STATS']['CPU']['cpu_cores_used'], 0.5)
            elif mode == 'stage':
                env.assertEqual(proc.returncode, 2, message=stderr)
                env.assertContains('connection-stage failures', stderr)
            else:
                env.assertContains('Interrupted by user (Ctrl+C)', stderr)
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.communicate()
            peer.close()


def test_unix_backlog_recovers(env):
    run_case(env, 'recover')


def test_unix_backlog_connection_timeout(env):
    run_case(env, 'timeout')


def test_unix_backlog_stage_timeout(env):
    run_case(env, 'stage')


def test_unix_backlog_interrupt(env):
    run_case(env, 'interrupt')
