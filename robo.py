#!/usr/bin/env python3
"""
Correct RoboForm password generator based on nullsecurity.org reverse engineering.
MSVC srand/rand LCG, random-buffer character placement, seed_mod mechanism.
Test vector: timestamp 1368634240, len=20, upper+lower+digits, no specials, min_digits=1
  -> "mAIQf0REsR3RRP43UHRx"
"""

import sys

CHARSETS = {
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "upper_similar": "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "lower_similar": "abcdefghijkmnopqrstuvwxyz",
    "digit": "0123456789",
    "digit_similar": "23456789",
    "hex": "0123456789ABCDEF",
    "hex_similar": "23456789ABCDEF",
    "special": "!@#$%^&*",
}


class RoboForm:
    def __init__(
        self,
        pass_length=8,
        chr_upper=True,
        chr_lower=True,
        chr_digits=True,
        chr_specials="!@#$%^&*",
        chr_similar=False,
        min_digits=1,
    ):
        self.seed_mod = 0

        if pass_length > 0x200:
            pass_length = 0x200
        self.pass_length = pass_length

        self.config = 0
        if chr_upper:
            self.config |= 0x01
        if chr_lower:
            self.config |= 0x02
        if chr_digits:
            self.config |= 0x04
        if chr_specials:
            self.config |= 0x08
        if chr_similar:
            self.config |= 0x20

        self.special_chars = chr_specials if chr_specials else ""
        self.min_digits = min_digits

    def srand(self, seed):
        self.seed = seed

    def rand(self):
        self.seed = ((0x000343FD * self.seed) + 0x00269EC3) & 0xFFFFFFFF
        return (self.seed >> 0x10) & 0x7FFF

    def rand_range(self, range_val):
        return (self.rand() * range_val) // 0x8000

    def rand_char(self, charset):
        return charset[self.rand_range(len(charset))]

    def _build_charsets(self):
        if self.config & 0x20:
            upper_cs = CHARSETS["upper_similar"]
            lower_cs = CHARSETS["lower_similar"]
            digit_cs = CHARSETS["digit_similar"]
            hex_cs = CHARSETS["hex_similar"]
        else:
            upper_cs = CHARSETS["upper"]
            lower_cs = CHARSETS["lower"]
            digit_cs = CHARSETS["digit"]
            hex_cs = CHARSETS["hex"]

        charset_full = ""
        if self.config & 0x01:
            charset_full += upper_cs
        if self.config & 0x02:
            charset_full += lower_cs
        if self.config & 0x04:
            charset_full += digit_cs
        if self.config & 0x08:
            charset_full += self.special_chars
        if self.config & 0x10:
            charset_full = hex_cs

        return upper_cs, lower_cs, digit_cs, charset_full

    def generate_character(self, password, flag, charset):
        if self.pass_length_ctr == 0:
            return
        if not (self.config & flag):
            return

        while True:
            idx = self.rand_range(self.pass_length)
            if password[idx] == '\0':
                break

        password[idx] = self.rand_char(charset)
        self.pass_length_ctr -= 1

    def generate(self, timestamp):
        self.srand(timestamp - self.seed_mod)
        self.seed_mod -= 0x000E3A78

        upper_cs, lower_cs, digit_cs, charset_full = self._build_charsets()

        password = ['\0'] * self.pass_length
        self.pass_length_ctr = self.pass_length

        for _ in range(self.min_digits):
            self.generate_character(password, 0x04, digit_cs)

        if self.special_chars:
            self.generate_character(password, 0x08, self.special_chars)

        self.generate_character(password, 0x01, upper_cs)
        self.generate_character(password, 0x02, lower_cs)

        if self.min_digits == 0:
            self.generate_character(password, 0x04, digit_cs)

        for i in range(self.pass_length):
            if password[i] == '\0':
                password[i] = self.rand_char(charset_full)

        return ''.join(password)


def test():
    rf = RoboForm(
        pass_length=20,
        chr_upper=True,
        chr_lower=True,
        chr_digits=True,
        chr_specials="",
        chr_similar=False,
        min_digits=1,
    )
    pw = rf.generate(1368634240)
    expected = "mAIQf0REsR3RRP43UHRx"
    status = "PASS" if pw == expected else "FAIL"
    print(f"[{status}] ts=1368634240 got={pw} expected={expected}", file=sys.stderr)

    # Verify surrounding timestamps from the article
    # Each timestamp needs a FRESH instance (seed_mod=0 for each program launch)
    tests = {
        1368634230: "p3GIGizgB69sost0r0Yr",
        1368634234: "CehHYh0NFDoH9464lOSg",
        1368634240: "mAIQf0REsR3RRP43UHRx",
        1368634249: "Mpjd1WmxDQVFwXc3XZim",
    }
    for ts, exp in tests.items():
        rft = RoboForm(
            pass_length=20,
            chr_upper=True,
            chr_lower=True,
            chr_digits=True,
            chr_specials="",
            chr_similar=False,
            min_digits=1,
        )
        pw2 = rft.generate(ts)
        s = "PASS" if pw2 == exp else "FAIL"
        print(f"  [{s}] ts={ts} got={pw2} expected={exp}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test()
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "--generate-range":
        start_ts = int(sys.argv[2])
        end_ts = int(sys.argv[3])
        length = int(sys.argv[4]) if len(sys.argv) > 4 else 16
        upper = sys.argv[5] != "0" if len(sys.argv) > 5 else True
        lower = sys.argv[6] != "0" if len(sys.argv) > 6 else True
        digits = sys.argv[7] != "0" if len(sys.argv) > 7 else True
        specials = sys.argv[8] if len(sys.argv) > 8 else "!@#$%^&*"
        similar = sys.argv[9] != "0" if len(sys.argv) > 9 else False
        min_digits = int(sys.argv[10]) if len(sys.argv) > 10 else 1

        rf = RoboForm(
            pass_length=length,
            chr_upper=upper,
            chr_lower=lower,
            chr_digits=digits,
            chr_specials=specials,
            chr_similar=similar,
            min_digits=min_digits,
        )
        for ts in range(start_ts, end_ts + 1):
            pw = rf.generate(ts)
            print(pw)
        sys.exit(0)

    # Default: read single timestamp from args
    if len(sys.argv) > 1:
        timestamp = int(sys.argv[1])
        length = int(sys.argv[2]) if len(sys.argv) > 2 else 16
        upper = sys.argv[3] != "0" if len(sys.argv) > 3 else True
        lower = sys.argv[4] != "0" if len(sys.argv) > 4 else True
        digits = sys.argv[5] != "0" if len(sys.argv) > 5 else True
        specials = sys.argv[6] if len(sys.argv) > 6 else "!@#$%^&*"
        similar = sys.argv[7] != "0" if len(sys.argv) > 7 else False
        min_digits = int(sys.argv[8]) if len(sys.argv) > 8 else 1

        rf = RoboForm(
            pass_length=length,
            chr_upper=upper,
            chr_lower=lower,
            chr_digits=digits,
            chr_specials=specials,
            chr_similar=similar,
            min_digits=min_digits,
        )
        print(rf.generate(timestamp))
    else:
        print("Usage:", file=sys.stderr)
        print("  python roboform.py --test", file=sys.stderr)
        print("  python roboform.py <timestamp> [length=16] [upper=1] [lower=1] [digits=1] [specials='!@#$%^&*'] [similar=0] [min_digits=1]", file=sys.stderr)
        print("  python roboform.py --generate-range <start_ts> <end_ts> [length=16] [upper=1] [lower=1] [digits=1] [specials='!@#$%^&*'] [similar=0] [min_digits=1]", file=sys.stderr)
        sys.exit(1)
