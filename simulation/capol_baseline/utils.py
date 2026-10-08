from Crypto.Util.number import bytes_to_long
import random


class AES_Random:
    # random number generator based on AES with ECB mode

    def __init__(self, key):
        self.count = bytes_to_long(key)

    def ceil(self, a, b):  # function for ceil(a / b)
        return (a // b) + (a % b > 0)

    def random_bytes(self, n_bytes):
        self.count+=1
        random.seed(self.count)
        return random.randbytes(n_bytes)

    def randint(
        self, n
    ):  # return a random integer 0 <= r <= n, assumes that 0 <= n < 256 (in our case n is at most 256 - 11)
        r = n + 1
        while r > n:
            rb = self.random_bytes(
                1
            )  # only generate one random byte as n is always < 256 in our case
            r = int.from_bytes(rb, "big")
        return r

    def random_nonzero_bytes(self, n_bytes):  # generate n_bytes nonzero bytes
        remaining = n_bytes
        res = b""
        while len(res) < n_bytes:
            r_bytes = self.random_bytes(
                remaining
            )  # generate remaining number of bytes we need
            res += self.remove_zero_bytes(r_bytes)  # filter out zero bytes
            remaining = n_bytes - len(
                res
            )  # update how many remaining bytes we need

        return res

    def remove_zero_bytes(self, bytes):  # filter out zero bytes
        res = b""
        for i in range(len(bytes)):
            if bytes[i] != 0:
                res += bytes[i : i + 1]
        return res
