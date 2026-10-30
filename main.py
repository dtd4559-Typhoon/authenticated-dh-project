"""Run the required demonstrations and record measured performance results."""

import argparse
import csv
import importlib.metadata
import json
import platform
import sys
import time
from pathlib import Path

from authentication import ProtocolError
from eve import change_field, unauthenticated_fixture
from parameters import generate_prime, prime_factors, find_generator
from participant import trusted_setup, abort_session
from protocol import (complete_exchange, start_exchange, receive_init,
                      receive_response)


def timed_parameters(bits):
    start = time.perf_counter()
    p = generate_prime(bits)
    prime_time = time.perf_counter() - start
    start = time.perf_counter()
    factors = prime_factors(p - 1)
    factor_time = time.perf_counter() - start
    start = time.perf_counter()
    g = find_generator(p, factors)
    generator_time = time.perf_counter() - start
    return p, g, factors, prime_time, factor_time, generator_time


def authenticated_demo(bits=16, fixture=False, debug=False):
    alice, bob = trusted_setup()
    print("=== SUCCESSFUL AUTHENTICATED EXCHANGE ===")
    if fixture:
        p, g, factors = 23, 5, {2, 11}
        print("Explicit mathematical test fixture: p=23, g=5")
    else:
        p, g, factors, prime_time, factor_time, generator_time = timed_parameters(bits)
        print(f"Requested prime size: {bits} bits")
        print("Modulus: generated using library prime generator")
        print(f"Prime generation (s): {prime_time:.9f}")
        print(f"Factorization (s): {factor_time:.9f}")
        print(f"Generator search (s): {generator_time:.9f}")
    print(f"Public modulus p: {p}")
    print(f"Modulus bit length: {p.bit_length()}")
    print(f"Distinct factors of p - 1: {sorted(factors)}")
    print(f"Public generator g: {g}")
    result = complete_exchange(alice, bob, bits, fixture, (p, g))
    for label, raw in zip(("INIT", "RESPONSE", "FINISH"), result["messages"]):
        print(f"Public {label} message: {raw.decode('utf-8')}")
    print("Received modulus library validation: PASS")
    print("Generator: validated")
    print("Alice initiation signature: VALID")
    print("Bob response signature: VALID")
    print("Alice finish signature: VALID")
    print("Transcript authenticated: " + ("YES" if result["authenticated"] else "NO"))
    print("Shared-secret equality in local test: " + ("PASS" if result["secrets_match"] else "FAIL"))
    print("Explicit key confirmation: NOT IMPLEMENTED")
    print("Private exponents and shared secret: HIDDEN")
    if debug:
        print("CLASSROOM DEBUG ONLY - not a public network message")
        print(f"Local Alice shared secret: {alice['shared_secret']}")
        print(f"Local Bob shared secret: {bob['shared_secret']}")
    if not result["authenticated"] or not result["secrets_match"]:
        raise RuntimeError("exchange did not meet its success criteria")
    return result


def attack_demo():
    print("=== UNAUTHENTICATED EVE ATTACK: FIXED CLASSROOM FIXTURE ===")
    result = unauthenticated_fixture()
    print(f"Public A={result['A']}, B={result['B']}")
    print(f"Eve sends E1={result['E1']} to Alice and E2={result['E2']} to Bob")
    print("CLASSROOM DEBUG ONLY - local fixture secrets, never sent over the network")
    print(f"Alice local secret: {result['alice_secret']}; Eve's matching local secret: {result['eve_alice_secret']}")
    print(f"Bob local secret: {result['bob_secret']}; Eve's matching local secret: {result['eve_bob_secret']}")
    assert result["alice_secret"] == result["eve_alice_secret"] == 6
    assert result["bob_secret"] == result["eve_bob_secret"] == 15
    print("Alice and Bob hold different secrets; Eve knows both.")
    print("=== SAME SUBSTITUTION AGAINST AUTHENTICATED VERSION ===")
    alice, bob = trusted_setup()
    init = start_exchange(alice, test_fixture=True)
    response = receive_init(bob, init, test_fixture=True)
    changed = change_field(response, "B", 17)
    print("Eve modified Bob's public value from 19 to 17.")
    try:
        receive_response(alice, changed)
    except ProtocolError as error:
        # The local coordinator also discards Bob's now-abandoned session.
        abort_session(bob)
        print("Bob response signature: INVALID")
        print("Exchange aborted: " + str(error))
        print("Alice usable secret after rejection: NONE")
        print("Bob abandoned pending state: CLEARED by local coordinator")
    else:
        raise RuntimeError("tampered response was incorrectly accepted")


def benchmark(trials=3, output_dir="results"):
    if type(trials) is not int or trials < 3:
        raise ValueError("record at least three trials per required size")
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    alice, bob = trusted_setup()
    rows = []
    for bits in (16, 24, 32):
        for trial in range(1, trials + 1):
            p, g, factors, prime_time, factor_time, generator_time = timed_parameters(bits)
            result = complete_exchange(alice, bob, bits, parameters=(p, g))
            if not result["authenticated"] or not result["secrets_match"]:
                raise RuntimeError("benchmark exchange failed")
            rows.append({"bits": bits, "trial": trial, "p": p, "g": g,
                         "prime_generation_s": prime_time,
                         "factorization_s": factor_time,
                         "generator_search_s": generator_time,
                         "authenticated": result["authenticated"],
                         "secrets_match": result["secrets_match"]})
    with (folder / "performance.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    environment = {"python": sys.version, "platform": platform.platform(),
                   "processor": platform.processor(),
                   "cryptography": importlib.metadata.version("cryptography"),
                   "pycryptodome": importlib.metadata.version("pycryptodome"),
                   "timer": "time.perf_counter", "trials_per_size": trials}
    (folder / "environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
    summary = ["# Measured performance", "", "These are actual local runs; timings vary.", "",
               "| Bits | Trial | Prime generation (s) | Factorization (s) | Generator search (s) | Authenticated | Secrets match |",
               "|---|---|---|---|---|---|---|"]
    for row in rows:
        summary.append(f"| {row['bits']} | {row['trial']} | {row['prime_generation_s']:.9f} | {row['factorization_s']:.9f} | {row['generator_search_s']:.9f} | Yes | Yes |")
    summary += ["", "## Timing variation", "",
                "Ranges and means below describe these runs, not guaranteed runtimes.", ""]
    for bits in (16, 24, 32):
        for field in ("prime_generation_s", "factorization_s", "generator_search_s"):
            values = [r[field] for r in rows if r["bits"] == bits]
            summary.append(f"- {bits} bits, {field}: min {min(values):.9f}, mean {sum(values)/len(values):.9f}, max {max(values):.9f} seconds.")
    summary += ["", "Library prime generation varies with random candidates; factorization varies with p - 1; generator search varies with the first passing candidate. Timer resolution, scheduling, and cache effects also matter. This small sample is not a reliable scaling study.",
                "", "Factorization and generator search are measured as separate stages. The generator function independently recomputes the complete factors for defensive checking, so its duration includes that verification. Bob's independent received-parameter validation occurs in each exchange but is not included in Alice's parameter-generation stage timings.",
                "", "See environment.json for the exact Python, OS, processor, and dependency versions."]
    (folder / "performance.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    return rows


def main():
    parser = argparse.ArgumentParser(description="Classroom authenticated Diffie-Hellman")
    parser.add_argument("--mode", choices=("all", "authenticated", "attacks", "benchmark"), default="all")
    parser.add_argument("--bits", type=int, default=16, help="exact prime size, 16 through 32")
    parser.add_argument("--fixture", action="store_true", help="explicit small p=23 teaching fixture")
    parser.add_argument("--debug", action="store_true", help="show labeled LOCAL shared secrets")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--output-dir", default="results")
    args = parser.parse_args()
    try:
        if args.mode in ("all", "authenticated"):
            authenticated_demo(args.bits, args.fixture, args.debug)
        if args.mode in ("all", "attacks"):
            attack_demo()
        if args.mode == "benchmark":
            benchmark(args.trials, args.output_dir)
    except (ValueError, TypeError) as error:
        parser.exit(1, "Error: " + str(error) + "\n")


if __name__ == "__main__":
    main()
