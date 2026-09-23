"""Measures the token verification path.

Recorded on 2026-09-23 (PyJWT 2.10.1, HS256, 324-byte token):

    full decode+verify   27.30 us
      raw HMAC (C)        3.38 us
      b64 + json (C)      6.82 us
      pure-Python glue   17.10 us

A native rewrite could reclaim about 22 us. The user lookup that follows
costs 200-500 us against Postgres, so verification is roughly 1% of a
request. Re-run this before considering a Rust backend: the trigger is
verification exceeding 5% of request time in a real deployment.
"""

import time

import jwt

KEY = "x" * 64


def bench(fn, n=20000):
    for _ in range(1000):
        fn()
    runs = []
    for _ in range(5):
        start = time.perf_counter_ns()
        for _ in range(n):
            fn()
        runs.append((time.perf_counter_ns() - start) / n)
    return min(runs)


def main() -> None:
    payload = {
        "sub": "12345",
        "jti": "a" * 32,
        "sid": "b" * 32,
        "typ": "access",
        "exp": int(time.time()) + 300,
    }
    token = jwt.encode(payload, KEY, algorithm="HS256")
    micros = bench(lambda: jwt.decode(token, KEY, algorithms=["HS256"])) / 1000
    print(f"full decode+verify: {micros:6.2f} us")


if __name__ == "__main__":
    main()
