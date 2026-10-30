#!/usr/bin/env python3
'''TLS Retry Test - measures whether clients retry with a new PreMasterSecret after handshake failure.'''

import argparse
import http.server
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time
import uuid
from datetime import datetime
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, TLS_Ext_SupportedVersion_CH, TLS_Ext_ALPN
)

sys.stdout.reconfigure(line_buffering=True)

SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
TOKEN_DATA = {}  # token -> {connections: [{timestamp, ciphertext_hash}], user_agent, ja4, last_seen}
TOKEN_LOCK = threading.Lock()
FILE_LOCK = threading.Lock()
BROWSERS = ['mozilla', 'chrome', 'safari',
            'firefox', 'edge', 'opera', 'webkit']
HTML = '''<!DOCTYPE html>
<html><head><title>TLS Retry Test</title></head>
<body>
<h1>Testing TLS retry behavior...</h1>
<img src="{url}" style="display:none"
     onerror="document.getElementById('s').textContent='Complete'">
<p id="s">In progress...</p>
</body></html>'''

GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

RSA_KEY_EXCHANGE_CIPHERS = {
    0x009d, 0xc0a1, 0xc09d, 0x003d, 0x0035, 0x00c0, 0x0084, 0xc03d,
    0xc051, 0xc07b, 0xc0a0, 0xc09c, 0x009c, 0x003c, 0x002f, 0x00ba,
    0x0096, 0x0041, 0x0007, 0xc03c, 0xc050, 0xc07a, 0x0005, 0x0004,
    0x000a, 0x0062, 0x0009, 0x0061, 0x0064, 0x0060, 0x0008, 0x0006,
    0x0003, 0x003b, 0x0002, 0x0001,
}


def generate_ca_and_cert(domain, ca_cert_path='ca.pem', ca_key_path='ca-key.pem'):
    '''Generate a local CA (or reuse existing) and a server cert signed by it.'''
    if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
        # Reuse existing CA
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        ca_name = ca_cert.subject
        print('Reusing existing CA.')
    else:
        # Generate new CA
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TLS Retry Test CA')])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2025, 1, 1))
            .not_valid_after(datetime(2030, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        with open(ca_cert_path, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(ca_key_path, 'wb') as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        print('Generated new CA.')

    # 2. Generate server cert signed by CA with wildcard SAN
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'*.{domain}')])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1))
        .not_valid_after(datetime(2030, 1, 1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f'*.{domain}'),
                x509.DNSName(domain),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_der = srv_cert.public_bytes(serialization.Encoding.DER)
    return cert_der, srv_key


def parse_client_hello(data):
    '''Parse TLS ClientHello and extract token, JA4 fingerprint, and RSA support.'''
    try:
        pkt = TLSClientHello(data[5:])

        token = None
        has_sni = False
        alpn = None
        tls13 = False

        for ext in pkt.ext or []:
            if isinstance(ext, TLS_Ext_ServerName):
                has_sni = True
                sn = ext.servernames[0].servername
                sni = sn.decode() if isinstance(sn, bytes) else sn
                token = sni.split('.')[0]
            elif isinstance(ext, TLS_Ext_SupportedVersion_CH):
                if 0x0304 in ext.versions:
                    tls13 = True
            elif isinstance(ext, TLS_Ext_ALPN):
                if ext.protocols:
                    p = ext.protocols[0]
                    if hasattr(p, 'protocol'):
                        alpn = p.protocol.decode() if isinstance(p.protocol, bytes) else p.protocol
                    elif isinstance(p, bytes):
                        alpn = p.decode()
                    else:
                        alpn = str(p)

        ciphers = [c for c in pkt.ciphers if c not in GREASE]
        ext_types = [
            e.type for e in (pkt.ext or [])
            if e.type not in GREASE and e.type not in (0, 16)
        ]

        supports_rsa = any(c in RSA_KEY_EXCHANGE_CIPHERS for c in ciphers)

        ver = '13' if tls13 else '12'
        sni_char = 'd' if has_sni else 'i'
        alpn_char = alpn[0] if alpn else '0'

        part_a = f't{ver}{sni_char}{len(ciphers):02d}{len(ext_types):02d}{alpn_char}'
        cipher_str = ','.join(f'{c:04x}' for c in sorted(ciphers))
        ext_str = ','.join(f'{e:04x}' for e in sorted(ext_types))
        part_b = sha256(cipher_str.encode()).hexdigest()[:12]
        part_c = sha256(ext_str.encode()).hexdigest()[:12]

        return token, f'{part_a}_{part_b}_{part_c}', supports_rsa
    except:
        pass
    return None, None, False


# --- TLS record/message construction ---

def tls_record(content_type, payload):
    '''Wrap payload in a TLS record: type(1) + version(2) + length(2) + payload.'''
    return struct.pack('!BHH', content_type, 0x0303, len(payload)) + payload


def handshake_msg(msg_type, payload):
    '''Construct a TLS handshake message: type(1) + length(3) + payload.'''
    length = len(payload)
    return struct.pack('!B', msg_type) + length.to_bytes(3, 'big') + payload


def build_server_hello(session_id=b''):
    '''Build ServerHello message selecting TLS_RSA_WITH_AES_128_CBC_SHA.'''
    server_random = os.urandom(32)
    # version 3,3 (TLS 1.2)
    payload = struct.pack('!BB', 3, 3)
    payload += server_random
    # session_id
    payload += struct.pack('!B', len(session_id)) + session_id
    # cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
    payload += struct.pack('!H', 0x002f)
    # compression: null
    payload += struct.pack('!B', 0)
    return handshake_msg(0x02, payload)


def build_certificate(cert_der):
    '''Build Certificate handshake message containing a single certificate.'''
    # Single cert: length(3) + cert_der
    cert_entry = len(cert_der).to_bytes(3, 'big') + cert_der
    # Certificate list: total_length(3) + cert entries
    payload = len(cert_entry).to_bytes(3, 'big') + cert_entry
    return handshake_msg(0x0b, payload)


def build_server_hello_done():
    '''Build ServerHelloDone message (empty payload).'''
    return handshake_msg(0x0e, b'')


def build_alert(level, description):
    '''Build a TLS alert record.'''
    return tls_record(21, struct.pack('!BB', level, description))


def recv_full_record(sock, timeout=10):
    '''Receive a complete TLS record from the socket. Returns (content_type, payload) or None.'''
    sock.settimeout(timeout)
    try:
        header = b''
        while len(header) < 5:
            chunk = sock.recv(5 - len(header))
            if not chunk:
                return None
            header += chunk
        content_type = header[0]
        length = struct.unpack('!H', header[3:5])[0]
        payload = b''
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                return None
            payload += chunk
        return content_type, payload
    except (socket.timeout, ConnectionError, OSError):
        return None


# Same prime table as fastbleichenbacher/utils.py
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973, 10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163, 10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247, 10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331, 10333, 10337, 10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433, 10453, 10457, 10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531, 10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631, 10639, 10651, 10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723, 10729, 10733, 10739, 10753, 10771, 10781, 10789, 10799, 10831, 10837, 10847, 10853, 10859, 10861, 10867, 10883, 10889, 10891, 10903, 10909, 10937, 10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003, 11027, 11047, 11057, 11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117, 11119, 11131, 11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213, 11239, 11243, 11251, 11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317, 11321, 11329, 11351, 11353, 11369, 11383, 11393, 11399, 11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483, 11489, 11491, 11497, 11503, 11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617, 11621, 11633, 11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731, 11743, 11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821, 11827, 11831, 11833, 11839, 11863, 11867, 11887, 11897, 11903, 11909, 11923, 11927, 11933, 11939, 11941, 11953, 11959, 11969, 11971, 11981, 11987, 12007, 12011, 12037, 12041, 12043, 12049, 12071, 12073, 12097, 12101, 12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161, 12163, 12197, 12203, 12211, 12227, 12239, 12241, 12251, 12253, 12263, 12269, 12277, 12281, 12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377, 12379, 12391, 12401, 12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473, 12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527, 12539, 12541, 12547, 12553, 12569, 12577, 12583, 12589, 12601, 12611, 12613, 12619, 12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703, 12713, 12721, 12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821, 12823, 12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917, 12919, 12923, 12941, 12953, 12959, 12967, 12973, 12979, 12983, 13001, 13003, 13007, 13009, 13033, 13037, 13043, 13049, 13063, 13093, 13099, 13103, 13109, 13121, 13127, 13147, 13151, 13159, 13163, 13171, 13177, 13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267, 13291, 13297, 13309, 13313, 13327, 13331, 13337, 13339, 13367, 13381, 13397, 13399, 13411, 13417, 13421, 13441, 13451, 13457, 13463, 13469, 13477, 13487, 13499, 13513, 13523, 13537, 13553, 13567, 13577, 13591, 13597, 13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691, 13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751, 13757, 13759, 13763, 13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859, 13873, 13877, 13879, 13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933, 13963, 13967, 13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057, 14071, 14081, 14083, 14087, 14107, 14143, 14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221, 14243, 14249, 14251, 14281, 14293, 14303, 14321, 14323, 14327, 14341, 14347, 14369, 14387, 14389, 14401, 14407, 14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479, 14489, 14503, 14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561, 14563]


def check_divisibility(encrypted_pms):
    '''Check which primes from the table divide the ciphertext integer.'''
    c = int.from_bytes(encrypted_pms, 'big')
    return [p for p in PRIMES if c % p == 0]


def log_immediate(output_file, entry):
    '''Write a log entry immediately and flush.'''
    with FILE_LOCK:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
            f.flush()


def extract_client_key_exchange(payload):
    '''Extract the encrypted PMS from a handshake record that may contain multiple messages.
    Walks through concatenated handshake messages looking for ClientKeyExchange (0x10).'''
    offset = 0
    while offset + 4 <= len(payload):
        msg_type = payload[offset]
        hs_length = int.from_bytes(payload[offset+1:offset+4], 'big')
        hs_body = payload[offset+4:offset+4+hs_length]

        if msg_type == 0x10 and len(hs_body) >= 2:  # ClientKeyExchange
            pms_length = struct.unpack('!H', hs_body[:2])[0]
            if 2 + pms_length <= len(hs_body):
                return hs_body[2:2 + pms_length]

        offset += 4 + hs_length
        # Sanity check: if hs_length is absurdly large, this is encrypted data
        if hs_length > 8192:
            return None
    return None


class RetryHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(10)

        # 1. Receive ClientHello
        try:
            data = sock.recv(4096)
        except (socket.timeout, ConnectionError):
            return
        if not data or len(data) < 5:
            return

        token, ja4, supports_rsa = parse_client_hello(data)
        if not token:
            sock.close()
            return

        with SESSIONS_LOCK:
            session = SESSIONS.get(token)
        user_agent = session['user_agent'] if session else 'unknown'

        if not supports_rsa:
            print(f'  [{token[:8]}] No RSA KEX support from {user_agent[:50]}, closing', flush=True)
            sock.close()
            return

        # 2. Send ServerHello + Certificate + ServerHelloDone
        server_hello = build_server_hello()
        certificate = build_certificate(self.server.cert_der)
        server_hello_done = build_server_hello_done()

        # Bundle into a single TLS record (handshake content type = 22)
        hs_payload = server_hello + certificate + server_hello_done
        try:
            sock.sendall(tls_record(22, hs_payload))
        except (ConnectionError, OSError):
            return

        # 3. Receive ClientKeyExchange (+ ChangeCipherSpec + Finished)
        encrypted_pms = None
        records_received = 0
        print(f'  [{token[:8]}] Waiting for client records...', flush=True)
        while records_received < 5:
            result = recv_full_record(sock)
            if result is None:
                print(f'  [{token[:8]}] recv returned None after {records_received} records', flush=True)
                break
            content_type, payload = result
            records_received += 1
            print(f'  [{token[:8]}] Record #{records_received}: type={content_type} len={len(payload)}', flush=True)

            if content_type == 22:  # Handshake
                pms = extract_client_key_exchange(payload)
                if pms:
                    encrypted_pms = pms
                elif payload:
                    hs_type = payload[0]
                    hs_len = int.from_bytes(payload[1:4], 'big') if len(payload) >= 4 else -1
                    print(f'  [{token[:8]}] HS type=0x{hs_type:02x} hs_len={hs_len} record_len={len(payload)} first={payload[:8].hex()}', flush=True)
            elif content_type == 20:  # ChangeCipherSpec
                pass
            elif content_type == 21:  # Alert from client
                desc = payload[1] if len(payload) > 1 else -1
                print(f'  [{token[:8]}] Client alert: level={payload[0] if payload else "?"} desc={desc}', flush=True)
                break

            # Once we have the encrypted PMS and have seen CCS, send fatal alert
            if encrypted_pms and content_type == 20:
                break

        # If we got a Finished (encrypted, after CCS), read it too
        if encrypted_pms:
            result = recv_full_record(sock, timeout=5)
            # Ignore the encrypted Finished, we just needed the PMS

        if not encrypted_pms and records_received == 0:
            print(f'  [{token[:8]}] No records received after ServerHello', flush=True)

        ciphertext_hash = sha256(encrypted_pms).hexdigest()[:16] if encrypted_pms else None
        divisors = check_divisibility(encrypted_pms) if encrypted_pms else []

        # 4. Log immediately (before failing, so reset mode doesn't skip logging)
        now = time.time()

        with TOKEN_LOCK:
            if token not in TOKEN_DATA:
                TOKEN_DATA[token] = {
                    'connections': [],
                    'user_agent': user_agent,
                    'ja4': ja4,
                    'first_seen': now,
                    'last_seen': now,
                }
            TOKEN_DATA[token]['connections'].append({
                'timestamp': now,
                'ciphertext_hash': ciphertext_hash,
            })
            TOKEN_DATA[token]['last_seen'] = now
            conn_num = len(TOKEN_DATA[token]['connections'])

        div_str = f' div:{divisors}' if divisors else ''
        print(f'  [{token[:8]}] #{conn_num} {user_agent[:40]} '
              f'PMS:{ciphertext_hash or "none"}{div_str}', flush=True)

        log_immediate(self.server.output_file, {
            'timestamp': datetime.now().isoformat(),
            'token': token,
            'conn': conn_num,
            'user_agent': user_agent,
            'ja4': ja4,
            'ciphertext_hash': ciphertext_hash,
            'divisible_by': divisors,
        })

        # 5. Fail the handshake
        fail_mode = self.server.fail_mode
        try:
            if fail_mode == 'reset':
                # TCP RST - PR_CONNECT_RESET_ERROR (bucket 16)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                sock.close()
                return  # skip shutdown below
            elif fail_mode == 'close':
                # Graceful TCP close - PR_END_OF_FILE_ERROR (bucket 17)
                sock.shutdown(socket.SHUT_RDWR)
            elif fail_mode == 'alert':
                # handshake_failure (40) - SSL_ERROR_HANDSHAKE_FAILURE_ALERT (bucket 3)
                sock.sendall(build_alert(2, 40))
            elif fail_mode == 'bad_mac':
                # bad_record_mac (20) - SSL_ERROR_BAD_MAC_ALERT (bucket 1)
                sock.sendall(build_alert(2, 20))
            elif fail_mode == 'decode_error':
                # decode_error (50) - SSL_ERROR_DECODE_ERROR_ALERT (bucket 14)
                sock.sendall(build_alert(2, 50))
            elif fail_mode == 'internal_error':
                # internal_error (80) - SSL_ERROR_INTERNAL_ERROR_ALERT (bucket 18)
                sock.sendall(build_alert(2, 80))
            elif fail_mode == 'close_notify':
                # close_notify (0) - NOT in bucket list, may bypass intolerance
                sock.sendall(build_alert(1, 0))
            elif fail_mode == 'garbage':
                # Send random garbage as a TLS record - may trigger BAD_MAC_READ
                sock.sendall(tls_record(22, os.urandom(64)))
            else:
                sock.sendall(build_alert(2, 40))
        except (ConnectionError, OSError):
            pass
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


class FrontendHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        ua = self.headers.get('User-Agent', 'unknown')
        token = uuid.uuid4().hex[:16]

        with SESSIONS_LOCK:
            SESSIONS[token] = {'user_agent': ua, 'ts': time.time()}

        url = f'https://{token}.{self.server.domain}:{self.server.backend_port}/'
        is_browser = any(b in ua.lower() for b in BROWSERS)
        body = HTML.format(url=url) if is_browser else f'{url}\n'

        print(f'Redirect: {ua[:60]} -> {token}')
        self.send_response(200)
        self.send_header(
            'Content-Type', 'text/html' if is_browser else 'text/plain')
        self.send_header('Content-Length', len(body))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body.encode())


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True


def summary_writer(output_file, quiet_period):
    '''Background thread that writes summaries for tokens with no activity for quiet_period seconds.'''
    while True:
        time.sleep(5)
        now = time.time()
        finished = []

        with TOKEN_LOCK:
            for token, data in TOKEN_DATA.items():
                if now - data['last_seen'] > quiet_period:
                    finished.append((token, data.copy()))
            for token, _ in finished:
                del TOKEN_DATA[token]

        for token, data in finished:
            conns = data['connections']
            hashes = [c['ciphertext_hash'] for c in conns if c['ciphertext_hash']]
            unique = len(set(hashes))
            retries = len(conns) - 1
            changed = 'YES' if unique > 1 else 'NO'
            timing = [c['timestamp'] - data['first_seen'] for c in conns]

            print(f'\n=== [{token[:8]}] {data["user_agent"][:50]} ===')
            print(f'    {len(conns)} connections, {retries} retries, '
                  f'PMS changed: {changed} ({unique} unique)')
            print(f'    Timing: {[f"{t:.2f}s" for t in timing]}', flush=True)


def main():
    p = argparse.ArgumentParser(description='TLS Retry Behavior Test')
    p.add_argument('--frontend-port', type=int, default=8080)
    p.add_argument('--backend-port', type=int, default=8443)
    p.add_argument('--domain', default='localhost')
    p.add_argument('-o', '--output', default='results.jsonl')
    p.add_argument('-q', '--quiet-period', type=int, default=10,
                   help='Seconds of inactivity before writing summary (default: 10)')
    p.add_argument('--fail-mode',
                   choices=['reset', 'close', 'alert', 'bad_mac', 'decode_error',
                            'internal_error', 'close_notify', 'garbage'],
                   default='reset',
                   help='How to fail: reset (TCP RST), close (FIN), alert (handshake_failure), '
                        'bad_mac, decode_error, internal_error, close_notify, garbage')
    args = p.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    ca_path = os.path.join(script_dir, 'ca.pem')
    ca_key_path = os.path.join(script_dir, 'ca-key.pem')
    print('Setting up CA + server certificate...')
    cert_der, _key = generate_ca_and_cert(args.domain, ca_path, ca_key_path)
    print(f'Certificate ready (fail_mode={args.fail_mode}).')
    print(f'CA saved to: {ca_path}')
    print(f'Trust it with: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {ca_path}')

    backend = ThreadedTCP(('0.0.0.0', args.backend_port), RetryHandler)
    backend.cert_der = cert_der
    backend.fail_mode = args.fail_mode
    backend.output_file = args.output
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    print(f'Backend listening on port {args.backend_port}')

    threading.Thread(target=summary_writer, args=(args.output, args.quiet_period),
                     daemon=True).start()

    frontend = ThreadedHTTP(('0.0.0.0', args.frontend_port), FrontendHandler)
    frontend.domain = args.domain
    frontend.backend_port = args.backend_port
    print(f'Frontend listening on port {args.frontend_port}')
    print(f'Open http://localhost:{args.frontend_port}/ in a browser to test')

    try:
        frontend.serve_forever()
    except KeyboardInterrupt:
        print('Stopped')


if __name__ == '__main__':
    main()
