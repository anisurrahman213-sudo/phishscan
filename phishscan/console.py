"""Terminal colors"""
import sys


class C:
    on = sys.stdout.isatty()
    R = "\033[91m" if on else ""
    Y = "\033[93m" if on else ""
    G = "\033[92m" if on else ""
    B = "\033[94m" if on else ""
    M = "\033[95m" if on else ""
    D = "\033[2m" if on else ""
    BO = "\033[1m" if on else ""
    X = "\033[0m" if on else ""
