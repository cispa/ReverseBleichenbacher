#
# This code is based on code copyright Livia Capol, 2021
#

from legacy_attack.utils import precalculated_primes
import math
import legacy_attack.utils as utils

# === helper methods ===

TRIM_VALUE_THRESHOLD = 20
MAX_SIMPLE_TRIMMER = 50

def trimmer_umin(t: int, N: int, B: int):
    return (2 * t) // 3 + 1

def trimmer_umax(t: int, N: int, B: int):
    return utils.ceil_div(3 * t, 2) - 1

def iter_trimmers(N, B, cutoff):
    """
    Computes all trimmers that should be tested.
    """
    max_t = utils.ceil_div(2 * N, 9 * B)
    offset = 0
    for i in range(3, cutoff + 1):
        yield i
    while offset < len(utils.precalculated_primes) and utils.precalculated_primes[offset] < max_t:
        if utils.precalculated_primes[offset] > cutoff:
            yield utils.precalculated_primes[offset]
        offset += 1

def iter_trimmer_oracle_args(t: int, slack: int, N: int, B: int):
    """
    Compute all oracle arguments that should be tried for the given trimmer t and slack slack.
    Multiple arguments should be used since the oracle might produce false negatives.
    """
    t_inv = pow(t, -1, N)
    umin = trimmer_umin(t, N, B)
    umax = trimmer_umax(t, N, B)
    for s in range(1, slack + 1):
        if t - s < umin and t + s > umax:
            break
        if t - s >= umin and math.gcd(t - s, t) == 1:
            yield ((t - s) * t_inv) % N
        if t + s <= umax and math.gcd(t + s, t) == 1:
            yield ((t + s) * t_inv) % N

def check_trimmer_parallel(t: int, slack: int, N: int, B: int, oracle):
    """
    Check if a value t is a valid trimmer.
    There can be false negatives, especially for small t.
    Checking is done using parallel oracle queries.
    """
    work_queue = list()
    for arg in iter_trimmer_oracle_args(t, slack, N, B):
        work_queue.append((arg, True))
    work_queue = oracle.submit(work_queue)
    for _, is_trimmer in oracle.as_completed(work_queue):
        if is_trimmer:
            oracle.cancel(work_queue)
            return True
    return False

def check_trimmer(t: int, slack: int, N: int, B: int, oracle):
    for i in iter_trimmer_oracle_args(t, slack, N, B):
        if oracle.query(i):
            return True
    return False

def bin_search_trimmers(slack: int, low: int, high: int, t_inv: int, findmin: bool, N: int, oracle, bruteforce: int):
    """
    Binary search for trimmer bounds.
    """
    if low >= high:
        if findmin:
            return high
        else:
            return low
    else:
        if findmin:
            mid = (low + high) // 2
        else:
            mid = utils.ceil_div(low + high, 2)

    if high - low <= bruteforce:
        work_queue = [(i, i) for i in range(low, high+1)]
        work_queue = oracle.submit(work_queue)
        best = high if findmin else low
        for e, c in oracle.as_completed(work_queue):
            if c:
                if findmin and e < best:
                    best = e
                elif not findmin and e > best:
                    best = e
        return best

    if oracle.query((mid * t_inv) % N):
        if findmin:
            return bin_search_trimmers(slack, low, mid, t_inv, findmin, N, oracle, bruteforce)
        else:
            return bin_search_trimmers(slack, mid, high, t_inv, findmin, N, oracle, bruteforce)
    else:
        if findmin:
            for s in range(1, slack + 1):
                if mid - s >= low:
                    if oracle.query(((mid - s) * t_inv) % N):
                        return bin_search_trimmers(slack, low, mid - s, t_inv, findmin, N, oracle, bruteforce)
                else:
                    return bin_search_trimmers(slack, mid + 1, high, t_inv, findmin, N, oracle, bruteforce)
            return bin_search_trimmers(slack, mid + 1, high, t_inv, findmin, N, oracle, bruteforce)
        else:
            for s in range(1, slack + 1):
                if mid + s <= high:
                    if oracle.query(((mid + s) * t_inv) % N):
                        return bin_search_trimmers(slack, mid + s, high, t_inv, findmin, N, oracle, bruteforce)
                else:
                    return bin_search_trimmers(slack, low, mid - 1, t_inv, findmin, N, oracle, bruteforce)
            return bin_search_trimmers(slack, low, mid - 1, t_inv, findmin, N, oracle, bruteforce)

def find_low_high(t: int, slack: int, N: int, B: int, oracle, bruteforce: int):
    """
    Find the low and high bounds for a trimmer t.
    The slack is used for binary searching to avoid false-negatives influencing the results.
    The bruteforce parameter defines how large of a range is searched in parallel at the end instead of relying on binary search.

    Returns:
    --------
    tuple: lower bound, upper bound
    """
    global TRIM_VALUE_THRESHOLD
    t_inv = pow(t, -1, N)
    low = trimmer_umin(t, N, B)
    high = trimmer_umax(t, N, B)

    u_l = t
    u_h = t
    i = 0

    while True:
        new_u_l = bin_search_trimmers(slack, low, u_l, t_inv, True, N, oracle, bruteforce)
        new_u_h = bin_search_trimmers(slack, u_h, high, t_inv, False, N, oracle, bruteforce)
        a = (utils.pkcs_lower_bound(B) * t) // new_u_l
        b = (utils.pkcs_upper_bound(B) * t // new_u_h) + 1
        trim_value = (B - 1) / (b - a + 1)
        if trim_value > TRIM_VALUE_THRESHOLD or (new_u_h == u_h and new_u_l == u_l):
            break

        u_l = new_u_l
        u_h = new_u_h
        i = i + 1
    
    return new_u_l, new_u_h


# === Methods that should be used ===

def find_trimmers_parallel(config, rsa, oracle):
    # known divisor of plaintext
    lcm = 1
    # work queue for parallel oracle queries
    work_queue = list()
    # bounds on the plaintext
    low = None
    high = None
    B = utils.pkcs_compute_B((rsa.bits + 7) // 8)
    
    for possible_t in iter_trimmers(rsa.N, B, config.cutoff):
        for trimmer_arg in iter_trimmer_oracle_args(possible_t, config.trimmer_slack, rsa.N, B):
            work_queue.append((trimmer_arg, possible_t))
    work_queue = oracle.submit(work_queue)
    for val, is_trimmer in oracle.as_completed(work_queue):
        if not is_trimmer:
            continue
        lcm = math.lcm(lcm, val)
        if lcm >= config.cutoff:
            oracle.cancel(work_queue)
            break
    
    if lcm == 1:
        raise Exception("No trimmer found")
    
    while check_trimmer_parallel(lcm * 2, config.trimmer_slack * 4, rsa.N, B, oracle):
        lcm *= 2
        
    low, high = find_low_high(lcm, config.binary_search_slack, rsa.N, B, oracle, 16)
    
    return lcm, low, high

def find_trimmers(config, rsa, oracle):
    global MAX_SIMPLE_TRIMMER
    # known divisor of plaintext
    lcm = 1
    # bounds on the plaintext
    low = None
    high = None
    B = utils.pkcs_compute_B((rsa.bits + 7) // 8)
    
    trimmers = list()
    
    # simple trimmers
    max_t = utils.ceil_div(2 * rsa.N, 9 * B)
    for possible_t in range(3, config.cutoff + 1):
        if lcm % possible_t == 0:
            continue
        if check_trimmer(possible_t, config.trimmer_slack, rsa.N, B, oracle):
            trimmers.append(possible_t)
            lcm = math.lcm(lcm, possible_t)
            # small optimization for FFT where we perform better if we don't early abort
            if lcm >= config.cutoff and oracle.config.kind != "FFT": 
                break
    
    # primes
    for p in utils.precalculated_primes:
        if p <= config.cutoff:
            continue
        if p > max_t:
            break
        if lcm >= config.cutoff:
            break
        if lcm % p == 0:
            continue
        if check_trimmer(p, config.trimmer_slack, rsa.N, B, oracle):
            lcm = math.lcm(lcm, p)
    
    # Check for powers of found ts (match old implementation)
    # The old implementation checks for powers of primes found in lcm
    for p in [x for x in utils.precalculated_primes if x <= lcm]:
        if lcm % p == 0:
            while True:
                t = p * lcm
                if check_trimmer(t, config.trimmer_slack, rsa.N, B, oracle):
                    lcm = t
                else:
                    break
    
    if lcm == 1:
        raise Exception("No trimmer found")

    # ensure powers of 2 are found
    if lcm % 2 != 0:
        while check_trimmer(lcm * 2, (config.trimmer_slack - 1) * 4 + 1, rsa.N, B, oracle):
            lcm *= 2
    
    low, high = find_low_high(lcm, config.binary_search_slack, rsa.N, B, oracle, 0)
    
    return lcm, low, high
