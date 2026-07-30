# RoboForm Password Generator

Correct implementation of RoboForm password generation based on nullsecurity.org reverse engineering.

Exploits the vulnerability in RoboForm v7.9.0 and earlier which seeds the MSVC PRNG with `time(NULL)`, making all passwords deterministic from the generation timestamp. All 5 nullsecurity test vectors pass.

## Usage

```bash
# Run test vectors
python3 robo.py --test

# Generate password for a single timestamp
python3 robo.py 1368634240 [length=16] [upper=1] [lower=1] [digits=1] [specials='!@#$%^&*'] [similar=0] [min_digits=1]

# Generate passwords for a range of timestamps
python3 robo.py --generate-range <start_ts> <end_ts> [length=16] [upper=1] [lower=1] [digits=1] [specials='!@#$%^&*'] [similar=0] [min_digits=1]
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| length | 16 | Password length (max 512) |
| upper | 1 | Include uppercase letters (1=yes, 0=no) |
| lower | 1 | Include lowercase letters |
| digits | 1 | Include digits |
| specials | `!@#$%^&*` | Special characters to include |
| similar | 0 | Include similar-looking characters (1=yes, 0=no) |
| min_digits | 1 | Minimum number of digits required |

## How It Works

1. Seeds the MSVC PRNG (`srand`/`rand` LCG) with `timestamp - seed_mod`.
2. Builds the character set based on configuration flags.
3. Places required characters (digits, specials, upper, lower) at random positions.
4. Fills remaining positions with random characters from the full charset.
5. Decrements `seed_mod` by `0x000E3A78` for each subsequent generation.

## License

MIT
