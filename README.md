# RoboForm Password Generator (srand time-seeded PRNG)

Correct implementation of RoboForm password generation based on nullsecurity.org reverse engineering.

Exploits the vulnerability in RoboForm v7.9.0 and earlier which seeds the MSVC PRNG with `time(NULL)`, making all passwords deterministic from the generation timestamp.

## Usage

```
python3 robo.py --test
python3 robo.py 1368634240 [length=16] [upper=1] [lower=1] [digits=1] [specials='!@#$%^&*'] [similar=0] [min_digits=1]
python3 robo.py --generate-range <start_ts> <end_ts> [length=16] [upper=1] [lower=1] [digits=1] [specials='!@#$%^&*'] [similar=0] [min_digits=1]
```
