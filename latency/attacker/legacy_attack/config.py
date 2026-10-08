import logging

class BleichenbacherTrimmerConfig:
    
    def __init__(self, cutoff, trimmer_slack, binary_search_slack):
        # Trimmer search stops early once a value >= cutoff is found.
        self.cutoff = cutoff
        # Due too false-negatives in the oracle, allow some slack when testing trimmers.
        self.trimmer_slack = trimmer_slack
        # Due too false-negatives in the oracle, allow some slack when binary searching trimmer bounds.
        self.binary_search_slack = binary_search_slack

class BleichenbacherSearchConfig:
    
    def __init__(self):
        pass

class BleichenbacherBottomUpConfig:
    
    def __init__(self, parallel_bits, total_bits):
        # BottomUp does an N-ary search with N=2**parallel_bits.
        # Using an N-ary search allows breaking query dependencies at the cost of total queries.
        # Should be 1 for non-parallel configurations.
        self.parallel_bits = parallel_bits
        # Total bits to recover.
        # This is smaller than the bitwidth of N since we are not interested in padding bits.
        self.total_bits = total_bits

class BleichenbacherGeneralConfig:
    
    def __init__(self, parallel, log_level):
        # Tries to break dependencies between queries and use the async oracle api to process oracle queries in parallel.
        self.parallel = parallel
        self.log_level = log_level

class BleichenbacherOracleConfig:

    def __init__(self, kind):
        self.kind = kind

class BleichenbacherConfig:
    
    def __init__(self, trimmer: BleichenbacherTrimmerConfig, search: BleichenbacherSearchConfig, bottom_up: BleichenbacherBottomUpConfig, oracle: BleichenbacherOracleConfig, general: BleichenbacherGeneralConfig):
        # Configuration for the trimmer step.
        self.trimmer = trimmer
        # Configuration for the search step.
        self.search = search
        # Configuration for the bottom-up recovery step.
        self.bottom_up = bottom_up
        # Configuration for the oracle
        self.oracle = oracle
        # General configuration.
        self.general = general

import legacy_attack.utils as utils

def get_config_tls(rsa):
    return BleichenbacherConfig(
        BleichenbacherTrimmerConfig(
            50,
            2,
            3
        ),
        BleichenbacherSearchConfig(),
        BleichenbacherBottomUpConfig(
            1,
            8*46
        ),
        BleichenbacherOracleConfig("FFT"),
        BleichenbacherGeneralConfig(
            False,
            logging.INFO
        )
    )

def get_config_tls_parallel(rsa):
    return BleichenbacherConfig(
        BleichenbacherTrimmerConfig(
            50,
            2,
            3
        ),
        BleichenbacherSearchConfig(),
        BleichenbacherBottomUpConfig(
            4,
            8*46
        ),
        BleichenbacherOracleConfig("FFT"),
        BleichenbacherGeneralConfig(
            True,
            logging.INFO
        )
    )
