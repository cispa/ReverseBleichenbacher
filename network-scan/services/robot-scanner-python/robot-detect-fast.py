#!/usr/bin/env -S python3 -W ignore::DeprecationWarning

# Fast ROBOT check: sends only pms_good and pms_bad1 in parallel.

import argparse
import ipaddress
import math
import os
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def build_client_hello(hostname, tls_version=(3, 3), cipher_suites=None, record_version=(3, 1)):
    if not cipher_suites:
        raise ValueError("At least one cipher suite must be provided")

    def vb(num, length):
        return num.to_bytes(length, "big")

    ch_body = bytearray()
    ch_body += vb(tls_version[0] << 8 | tls_version[1], 2)
    ch_body += os.urandom(32)
    ch_body += b"\x00"

    suites = b"".join(vb(cs, 2) for cs in cipher_suites)
    ch_body += vb(len(suites), 2) + suites
    ch_body += b"\x01\x00"

    extensions = bytearray()

    if hostname:
        try:
            name_bytes = hostname.encode("idna")
        except UnicodeError:
            name_bytes = b""
        if name_bytes and len(name_bytes) <= 0xFFFF:
            sni_list = b"\x00" + vb(len(name_bytes), 2) + name_bytes
            sni_ext_data = vb(len(sni_list), 2) + sni_list
            extensions += vb(0x0000, 2) + vb(len(sni_ext_data), 2) + sni_ext_data

    sig_algs = bytearray.fromhex(
        "0601 0602 0603 0501 0502 0503 0401 0402 0403 0301 0302 0303 0201 0202 0203".replace(" ", "")
    )
    sig_body = vb(len(sig_algs), 2) + sig_algs
    extensions += vb(0x000D, 2) + vb(len(sig_body), 2) + sig_body

    ch_body += vb(len(extensions), 2) + extensions

    handshake = bytearray(b"\x01")
    handshake += vb(len(ch_body), 3)
    handshake += ch_body

    record = bytearray(b"\x16")
    record += vb(record_version[0] << 8 | record_version[1], 2)
    record += vb(len(handshake), 2)
    record += handshake
    return bytes(record)


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_rsa_from_server(server, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("RSA")

    server_hostname = None if is_ip_address(server) else server
    with socket.create_connection((server, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
            cert_raw = ssock.getpeercert(binary_form=True)
            cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
            pub = cert_dec.public_key().public_numbers()
            return ssock.cipher(), pub.n, pub.e, server_hostname is not None


ccs = bytearray.fromhex("000101")
enc = bytearray.fromhex(
    "005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0"
)


def recv_exact_record(sock, buf, offset):
    while offset + 5 > len(buf):
        data = sock.recv(4096)
        if not data:
            raise RuntimeError("Connection closed while reading TLS record header")
        buf += data
    size = buf[offset + 3] * 256 + buf[offset + 4]
    while offset + 5 + size > len(buf):
        data = sock.recv(4096)
        if not data:
            raise RuntimeError("Connection closed while reading TLS record payload")
        buf += data
    return size, buf


def oracle_once(ip, port, client_hello, cke_2nd_prefix, pms, timeout):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(client_hello)

        buf = bytearray()
        offset = 0
        while True:
            size, buf = recv_exact_record(sock, buf, offset)
            if size == 2:
                alert_level = buf[offset + 5]
                alert_description = buf[offset + 6]
                return "Alert(%i, %i) after ClientHello" % (alert_description, alert_level)
            if (buf[offset + 5] == 0x0E) or (buf[len(buf) - 4] == 0x0E):
                break
            offset += size + 5

        cke_version = bytes(buf[9:11])
        sock.sendall(bytearray(b"\x16") + cke_version)
        sock.sendall(cke_2nd_prefix)
        sock.sendall(pms)
        sock.sendall(bytearray(b"\x14") + cke_version + ccs)
        sock.sendall(bytearray(b"\x16") + cke_version + enc)

        alert = sock.recv(4096)
        if len(alert) == 0:
            return "No response"
        if alert[0] == 0x15:
            if len(alert) < 7:
                return "TLS alert was truncated (%s)" % (repr(alert))
            # return "TLS alert %i of length %i" % (alert[6], len(alert))
            return "TLS alert %i" % (alert[6])
        return "Received non-alert response (%s)" % (alert[0:10],)
    except Exception as e:
        # return str(e)
        return "Exception"
    finally:
        if sock is not None:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description="Fast ROBOT check (good vs bad1 only, parallel)")
    parser.add_argument("host", help="Target host")
    parser.add_argument("-p", "--port", type=int, default=443, help="TCP port")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Socket timeout")
    parser.add_argument("--gcm", action="store_true", help="Use only GCM/AES256")
    parser.add_argument("--cbc", action="store_true", help="Use only CBC/AES128")
    parser.add_argument("--csv", action="store_true", help="Output CSV")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror as e:
        if args.csv:
            print("NODNS,%s,,,,,,,,," % (args.host,))
            return 0
        print("Cannot resolve host: %s" % e)
        return 1

    if not args.quiet:
        print("Scanning host %s ip %s port %i" % (args.host, ip, args.port))

    try:
        negotiated_cipher, n, e, use_sni = get_rsa_from_server(args.host, args.port)
    except ssl.SSLError as err:
        if args.csv:
            print("NORSA,%s,%s,,,,,,,," % (args.host, ip))
            return 0
        print("Cannot connect to server: %s" % err)
        print("Server does not seem to allow connections with TLS_RSA.")
        return 0
    except (ConnectionRefusedError, socket.timeout, OSError) as err:
        if args.csv:
            print("NOTLS,%s,%s,,,,,,,," % (args.host, ip))
            return 0
        print("Cannot connect to server: %s" % err)
        return 0

    if args.gcm:
        ch = build_client_hello(args.host if use_sni else None, cipher_suites=[0x009C])
    elif args.cbc:
        ch = build_client_hello(args.host if use_sni else None, cipher_suites=[0x002F])
    else:
        ch = build_client_hello(
            args.host if use_sni else None,
            cipher_suites=[0x009D, 0x003D, 0x0035, 0x009C, 0x003C, 0x002F, 0x000A, 0x00FF],
        )

    modulus_bits = int(math.ceil(math.log(n, 2)))
    modulus_bytes = (modulus_bits + 7) // 8
    cke_2nd_prefix = bytearray.fromhex(
        "{0:0{1}x}".format(modulus_bytes + 6, 4)
        + "10"
        + "{0:0{1}x}".format(modulus_bytes + 2, 6)
        + "{0:0{1}x}".format(modulus_bytes, 4)
    )

    pad_len = (modulus_bytes - 48 - 3) * 2
    rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]
    rnd_pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"

    pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
    pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)

    pms_good = pow(pms_good_in, e, n).to_bytes(modulus_bytes, byteorder="big")
    pms_bad1 = pow(pms_bad_in1, e, n).to_bytes(modulus_bytes, byteorder="big")

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_good = executor.submit(oracle_once, ip, args.port, ch, cke_2nd_prefix, pms_good, args.timeout)
        future_bad1 = executor.submit(oracle_once, ip, args.port, ch, cke_2nd_prefix, pms_bad1, args.timeout)
        result_good = future_good.result()
        result_bad1 = future_bad1.result()

    distinguishable = result_good != result_bad1
    tlsver = ""
    oracle_bad2 = ""
    oracle_bad3 = ""
    oracle_bad4 = ""

    if args.csv:
        if distinguishable:
            print(
                "VULNERABLE,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
                % (args.host, ip, tlsver, "unknown", "parallel", result_good, result_bad1, oracle_bad2, oracle_bad3, oracle_bad4)
            )
        else:
            print("SAFE,%s,%s,,,,%s,%s,%s,%s,%s" % (args.host, ip, result_good, result_bad1, oracle_bad2, oracle_bad3, oracle_bad4))
        return 0

    if distinguishable:
        print(
            "VULNERABLE! Oracle (%s) found on %s/%s, %s, %s message flow: %s/%s (%s / %s / %s)"
            % ("unknown", args.host, ip, tlsver, "parallel", result_good, result_bad1, oracle_bad2, oracle_bad3, oracle_bad4)
        )
    else:
        print("NOT VULNERABLE!")

    if not args.quiet:
        print("Result of good request:                        %s" % result_good)
        print("Result of bad request 1 (wrong first bytes):   %s" % result_bad1)
        print("Result of bad request 2 (wrong 0x00 position): %s" % oracle_bad2)
        print("Result of bad request 3 (missing 0x00):        %s" % oracle_bad3)
        print("Result of bad request 4 (bad TLS version):     %s" % oracle_bad4)
    return 0


if __name__ == "__main__":
    sys.exit(main())
