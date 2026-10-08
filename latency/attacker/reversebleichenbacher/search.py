#
# This code is based on code copyright Livia Capol, 2021
#

from typing import Tuple
import itertools
import gmpy2

import reversebleichenbacher.utils as utils

# === helper methods ===

EIGHT_ONEZERO_THRESHOLD = 256

def search_p_to_s(p: int, r: int, div: int, N: int) -> int:
    """Transforms a modulus into the offset s for step2a."""
    one = utils.inv(p, div, N) * div // N
    return (pow(one, -1, div) * r) % div

def search_iter_oracle_args(divisor, low, high, N, B):
    global EIGHT_ONEZERO_THRESHOLD
    r = 1
    a_lcm = utils.ceil_div(low, divisor)
    b_lcm = high // divisor
    div = 2

    # Issue 4: s is the odd numerator of the effective half-integer
    # multiplier. Keep twice the oracle endpoints exact for odd N.
    min_dist = N - 3 * B * div
    max_dist = N - 2 * B * div

    s_lower = (max_dist - b_lcm) // (div * b_lcm)
    s_upper = utils.ceil_div(max_dist, div * a_lcm)
    shifts = []
    highest_not_covered = b_lcm
    last_shift = s_lower - 1

    while highest_not_covered >= a_lcm:
        left, right = last_shift + 1, s_upper
        while left < right:
            shift = (left + right) // 2
            s = shift * div + search_p_to_s(1, r, div, N)
            lb, rb = utils.get_scaled_coverage(s, min_dist, max_dist)
            if rb < highest_not_covered:
                right = shift
            else:
                left = shift + 1

        # left is the first shift whose upper endpoint is below the
        # uncovered point. Use its predecessor to avoid skipping a slice.
        shift = max(last_shift + 1, left - 1)
        s = shift * div + search_p_to_s(1, r, div, N)
        lb, rb = utils.get_scaled_coverage(s, min_dist, max_dist)
        if lb > highest_not_covered:
            # Outside the proved b <= B regime, half-integer steps may
            # leave gaps. Retain the next partial slice for best effort.
            shift += 1
            s += div
            lb, rb = utils.get_scaled_coverage(s, min_dist, max_dist)

        shifts.append(s)
        last_shift = shift
        highest_not_covered = lb - 1

    covered_s = set()
    OOB_left = False
    OOB_right = False

    for i in itertools.count(0):
        offset = i * (-1) ** i
        offset = offset * div // 2
        if b_lcm < B // EIGHT_ONEZERO_THRESHOLD:
            offset *= utils.ceil_div(B // EIGHT_ONEZERO_THRESHOLD, b_lcm)
        skipped = 0

        if OOB_left and OOB_right:
            break

        for s in shifts:
            cur_s = s + 2 * offset
            if cur_s in covered_s:
                skipped += 1
                continue

            new_a, new_b = [x * divisor for x in utils.get_scaled_coverage(cur_s, min_dist, max_dist)]
            if new_a > high:
                OOB_right = True
                continue
            if new_b < low:
                OOB_left = True
                continue
            
            yield utils.inv(-cur_s, div * divisor, N), (new_a, new_b)
            covered_s.add(cur_s)

        if skipped == len(shifts):
            break

# === methods that should be called ===

def search(divisor, low, high, rsa, oracle, config):
    for arg, bounds in search_iter_oracle_args(divisor, low, high, rsa.N, utils.pkcs_compute_B((rsa.bits + 7) // 8)):
        if oracle.query(arg):
            low, high = max(low, bounds[0]), min(high, bounds[1])
            return low, high
    raise Exception("search failed")

def search_parallel(divisor, low, high, rsa, oracle, config):
    args = list(search_iter_oracle_args(divisor, low, high, rsa.N, utils.pkcs_compute_B((rsa.bits + 7) // 8)))
    while args:
        work_queue = oracle.submit(args[:256])
        args = args[256:]
        for bounds, c in oracle.as_completed(work_queue):
            if not c:
                continue
            oracle.cancel(work_queue)
            low, high = max(low, bounds[0]), min(high, bounds[1])
            return low, high
    raise Exception("search failed")
