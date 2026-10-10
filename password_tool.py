"""Project 4: Password generator and strength checker.

Usage:
    python password_tool.py generate                 # 16 chars, all character types
    python password_tool.py generate -l 24 --no-symbols
    python password_tool.py passphrase -w 5          # e.g. maple-river-cloud-stone-tiger
    python password_tool.py check "MyP@ssw0rd"       # rate a password
"""

import argparse
import math
import secrets
import string

WORDS = [
    "apple", "brave", "cloud", "drift", "eagle", "flame", "grape", "house",
    "ivory", "jolly", "lemon", "mango", "night", "ocean", "piano", "river",
    "stone", "tiger", "unity", "vivid", "whale", "zebra", "plant", "brick",
    "sweet", "light", "water", "maple", "amber", "coral", "frost", "harbor",
    "pixel", "rocket", "silver", "thunder", "velvet", "willow", "canyon", "meadow",
]

COMMON = {"password", "123456", "12345678", "qwerty", "letmein", "admin", "welcome", "iloveyou"}


def generate(length, symbols=True, digits=True):
    pools = [string.ascii_lowercase, string.ascii_uppercase]
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    if length < len(pools):
        raise SystemExit(f"Length must be at least {len(pools)}.")

    # Guarantee one character from each pool, then fill the rest randomly.
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def passphrase(words):
    return "-".join(secrets.choice(WORDS) for _ in range(words))


def check(pw):
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 30
    entropy = len(pw) * math.log2(pool) if pool else 0

    notes = []
    if pw.lower() in COMMON:
        entropy = min(entropy, 10)
        notes.append("is a very common password")
    if len(pw) < 12:
        notes.append("try 12+ characters")
    if len(set(pw)) < len(pw) / 2:
        notes.append("lots of repeated characters")
    if pw.isalpha() or pw.isdigit():
        notes.append("mix in other character types")

    if entropy < 40:
        rating = "weak"
    elif entropy < 60:
        rating = "okay"
    elif entropy < 80:
        rating = "strong"
    else:
        rating = "very strong"

    print(f"Rating:  {rating} (~{entropy:.0f} bits of entropy)")
    for n in notes:
        print(f"  - {n}")


def main():
    parser = argparse.ArgumentParser(description="Password generator and checker")
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="generate a random password")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--no-digits", action="store_true")

    p = sub.add_parser("passphrase", help="generate a word-based passphrase")
    p.add_argument("-w", "--words", type=int, default=4)

    c = sub.add_parser("check", help="rate a password's strength")
    c.add_argument("password")

    args = parser.parse_args()
    if args.command == "generate":
        print(generate(args.length, not args.no_symbols, not args.no_digits))
    elif args.command == "passphrase":
        print(passphrase(args.words))
    else:
        check(args.password)


if __name__ == "__main__":
    main()
