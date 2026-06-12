#!/usr/bin/env python3
"""
JWT-Focused 1,000,000-Entry Wordlist Generator
Generates a comprehensive, JWT-specific wordlist covering:
  - Common secrets, keys, passwords
  - Year/season/month combos
  - Leet-speak transforms
  - Numeric combos
  - Common dev patterns (secret123, mysecret, etc.)
  - 4–8 char alphanumeric brute patterns
"""

import itertools
import random
import string
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn, TimeElapsedColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich import box
    from rich.rule import Rule
    from rich.align import Align
except ImportError:
    print("[!] pip install rich")
    sys.exit(1)

console = Console(highlight=False)

TARGET = 1_000_000
OUTPUT_FILE = "jwt_wordlist.txt"

# ─────────────────────── Word Banks ──────────────────────────────────
COMMON_SECRETS = [
    "secret", "password", "pass", "key", "token", "jwt", "auth",
    "admin", "root", "user", "test", "demo", "dev", "prod", "stage",
    "mysecret", "mykey", "mypassword", "mytoken", "apikey", "api_key",
    "secretkey", "secret_key", "jwtkey", "jwt_key", "jwttoken", "jwt_token",
    "authkey", "auth_key", "authtoken", "auth_token",
    "supersecret", "super_secret", "verysecret", "very_secret",
    "changeme", "change_me", "changethis", "todo", "fixme",
    "default", "insecure", "unsafe", "unsafe123",
    "letmein", "letmein123", "iloveyou", "love",
    "qwerty", "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "abc123", "123abc", "1234", "12345", "123456", "1234567", "12345678",
    "123456789", "1234567890", "0000", "0000000", "111111", "222222",
    "password1", "password123", "password1234", "password12345",
    "pass123", "pass1234", "pass12345",
    "p@ssword", "p@ss", "p@ssw0rd", "passw0rd",
    "secret1", "secret12", "secret123", "secret1234",
    "token1", "token12", "token123", "token1234",
    "key1", "key12", "key123", "key1234",
    "admin123", "admin1234", "admin12345",
    "root123", "root1234", "user123",
    "test123", "test1234", "test12345",
    "dev123", "dev1234", "staging",
    "HS256", "HS384", "HS512", "RS256",
    "hello", "hello123", "hello1234",
    "world", "world123",
    "welcome", "welcome1", "welcome123",
    "master", "master123", "master_key", "masterkey",
    "private", "private_key", "privatekey",
    "public", "public_key",
    "hack", "hack123", "hacker", "hacking",
    "flask", "django", "rails", "express", "laravel", "spring",
    "node", "nodejs", "python", "ruby", "java", "golang",
    "mysql", "postgres", "mongo", "redis",
    "localhost", "127.0.0.1", "0.0.0.0",
    "production", "development", "testing", "staging",
    "app", "app_secret", "application", "webapp",
    "api", "api_secret", "apitoken", "api123",
    "bearer", "oauth", "oauth2", "openid",
    "access", "access_key", "access_token",
    "refresh", "refresh_token", "refresh_key",
    "session", "session_key", "session_secret",
    "cookie", "cookie_key", "cookie_secret",
    "signature", "signing", "signing_key",
    "crypto", "cipher", "hash", "hmac",
    "top_secret", "topsecret", "classified",
    "company", "corp", "inc", "ltd",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
    "january", "february", "march", "april", "june",
    "july", "august", "september", "october", "november", "december",
    "spring", "summer", "autumn", "winter", "fall",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "sun", "mon", "tue", "wed", "thu", "fri", "sat",
    "dragon", "batman", "superman", "spider", "ninja",
    "matrix", "shadow", "phantom", "ghost",
    "alpha", "beta", "gamma", "delta", "omega", "sigma",
    "hunter", "hunter2", "trustno1", "monkey", "football",
    "starwars", "star_wars", "pokemon", "minecraft",
    "x", "xx", "xxx", "xxxx",
    "a", "aa", "aaa", "aaaa",
    "", "null", "none", "undefined", "empty",
]

YEARS = [str(y) for y in range(2000, 2027)]
SEASONS = ["spring", "summer", "autumn", "winter", "fall"]
MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]

LEET_MAP = {
    'a': ['a', '@', '4'],
    'e': ['e', '3'],
    'i': ['i', '1', '!'],
    'o': ['o', '0'],
    's': ['s', '$', '5'],
    't': ['t', '7'],
    'g': ['g', '9'],
    'b': ['b', '6'],
    'l': ['l', '1'],
}

SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "@", "#", "##", "$", "$$",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "01", "02", "99", "00", "007",
    "_", "_1", "_123", "_secret", "_key",
]

PREFIXES = [
    "", "my", "the", "a", "an", "super", "ultra", "mega",
    "new", "old", "best", "top", "master",
]


# ─────────────────────── Generators ──────────────────────────────────
def gen_base_words():
    seen = set()
    for w in COMMON_SECRETS:
        if w and w not in seen:
            seen.add(w)
            yield w

def gen_leet(words):
    """Apply leet-speak transforms to words."""
    for word in words:
        yield word
        word_low = word.lower()
        for char, replacements in LEET_MAP.items():
            for rep in replacements[1:]:
                leet = word_low.replace(char, rep)
                if leet != word_low:
                    yield leet

def gen_prefix_suffix(words):
    for word in words:
        for pre in PREFIXES:
            for suf in SUFFIXES:
                combo = f"{pre}{word}{suf}"
                if combo:
                    yield combo

def gen_year_combos():
    for base in COMMON_SECRETS[:100]:
        for year in YEARS:
            yield f"{base}{year}"
            yield f"{year}{base}"

def gen_season_month():
    for s in SEASONS:
        for year in YEARS:
            yield f"{s}{year}"
            yield f"{s}_{year}"
    for m in MONTHS:
        for year in YEARS:
            yield f"{m}{year}"
            yield f"{m}_{year}"

def gen_numeric_patterns():
    """Pure numeric and simple alphanumeric patterns."""
    # 4-8 digit numbers
    for n in range(0, 10000):
        yield str(n).zfill(4)
    for n in range(0, 100000, 7):
        yield str(n).zfill(5)
    for n in range(100000, 1000000, 31):
        yield str(n)
    # hex-like patterns
    hex_chars = "0123456789abcdef"
    for length in range(4, 9):
        for _ in range(200):
            yield "".join(random.choices(hex_chars, k=length))

def gen_brute_short():
    """All combinations of lowercase+digits, lengths 1-5."""
    charset = string.ascii_lowercase + string.digits
    for length in range(1, 5):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)

def gen_brute_alpha5():
    """Random sample of 5-char alphanumeric combos (too many for full)."""
    charset = string.ascii_lowercase + string.digits
    for _ in range(200000):
        yield "".join(random.choices(charset, k=5))

def gen_common_patterns():
    """Common JWT/API key patterns from real breaches."""
    patterns = []
    # Pattern: word + special + number
    bases = ["secret", "key", "token", "pass", "auth", "api", "jwt", "admin", "user"]
    specials = ["", "!", "@", "#", "_", "-", "."]
    nums = ["1", "12", "123", "1234", "12345", "2021", "2022", "2023", "2024"]
    for b in bases:
        for s in specials:
            for n in nums:
                patterns.append(f"{b}{s}{n}")
                patterns.append(f"{b.capitalize()}{s}{n}")
                patterns.append(f"{b.upper()}{s}{n}")

    # UUID-like
    for _ in range(5000):
        parts = [
            "".join(random.choices(string.hexdigits.lower(), k=8)),
            "".join(random.choices(string.hexdigits.lower(), k=4)),
            "".join(random.choices(string.hexdigits.lower(), k=4)),
            "".join(random.choices(string.hexdigits.lower(), k=4)),
            "".join(random.choices(string.hexdigits.lower(), k=12)),
        ]
        patterns.append("-".join(parts))

    # base64-like noise
    b64_chars = string.ascii_letters + string.digits + "+/="
    for _ in range(10000):
        patterns.append("".join(random.choices(b64_chars, k=random.randint(16, 48))))

    return patterns

# ─────────────────────── Main Builder ────────────────────────────────
def build_wordlist():
    console.print(
        Panel(
            "[bold bright_green]JWT WORDLIST GENERATOR[/bold bright_green]\n"
            "[dim green]Generating 1,000,000 JWT-focused entries...[/dim green]",
            border_style="bright_green",
            box=box.DOUBLE,
            padding=(1, 4),
        )
    )

    seen = set()
    output_path = Path(OUTPUT_FILE)
    count = 0

    def collect(generator, desc, task, progress):
        nonlocal count
        for word in generator:
            w = str(word).strip()
            if w and w not in seen:
                seen.add(w)
                yield w
                count += 1
                if count % 50000 == 0:
                    progress.update(task, completed=min(count, TARGET))
            if count >= TARGET:
                return

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold green"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=50, style="green", complete_style="bright_green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[bright_green]Building wordlist...", total=TARGET)

        with open(output_path, "w") as f:
            stages = [
                ("Base words", gen_base_words()),
                ("Leet transforms", gen_leet(list(gen_base_words()))),
                ("Prefix+Suffix combos", gen_prefix_suffix(list(gen_base_words()))),
                ("Year combos", gen_year_combos()),
                ("Season/Month combos", gen_season_month()),
                ("Numeric patterns", gen_numeric_patterns()),
                ("Short brute (1-4)", gen_brute_short()),
                ("5-char alpha brute", gen_brute_alpha5()),
                ("Common patterns", iter(gen_common_patterns())),
            ]

            for desc, gen in stages:
                if count >= TARGET:
                    break
                progress.update(task, description=f"[bright_green]{desc}")
                for word in collect(gen, desc, task, progress):
                    f.write(word + "\n")
                    if count >= TARGET:
                        break

            # ── Fill remainder with random alphanumeric ──
            if count < TARGET:
                progress.update(task, description="[bright_green]Filling remaining with random")
                charset = string.ascii_letters + string.digits + "!@#$_-."
                while count < TARGET:
                    length = random.randint(3, 12)
                    word = "".join(random.choices(charset, k=length))
                    if word not in seen:
                        seen.add(word)
                        f.write(word + "\n")
                        count += 1
                        if count % 50000 == 0:
                            progress.update(task, completed=count)

        progress.update(task, completed=TARGET, description="[bold bright_green]Complete!")

    size_mb = output_path.stat().st_size / (1024 * 1024)

    console.print(
        Panel(
            f"[bold bright_green]✓ Wordlist Generated![/bold bright_green]\n\n"
            f"  [bold]File    :[/bold] [cyan]{output_path.resolve()}[/cyan]\n"
            f"  [bold]Entries :[/bold] [bright_green]{count:,}[/bright_green]\n"
            f"  [bold]Size    :[/bold] [bright_green]{size_mb:.1f} MB[/bright_green]",
            border_style="bright_green",
            padding=(1, 4),
        )
    )


if __name__ == "__main__":
    build_wordlist()
