import time
from multiprocessing import Pool, cpu_count, Manager
from datetime import datetime, timedelta
import sys

# MSVCRT rand() and srand() implementation
class MSVCRTRand:
    def __init__(self, seed=1):
        self.state = seed

    def srand(self, seed):
        self.state = seed

    def rand(self):
        # MSVCRT uses: state = (state * 214013 + 2531011) & 0xFFFFFFFF
        # then returns (state >> 16) & 0x7FFF
        self.state = (self.state * 214013 + 2531011) & 0xFFFFFFFF
        return (self.state >> 16) & 0x7FFF

def get_char_from_pool(rng, chars):
    return chars[rng.rand() % len(chars)]

def generate_passwords_for_day(args):
    current_date, min_length, max_length, include_symbols, progress = args
    
    # Character pools as loosely used in RoboForm 7
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = "!#%&()*+,-./:;<=>?@[]^_{|}~"
    
    chars = lowercase + uppercase + digits
    if include_symbols:
        chars += symbols

    passwords = []

    # RoboForm 7 versions prior to 7.9.14 seeded with time(NULL)
    # which is seconds since Jan 1, 1970
    time_struct = datetime.strptime(current_date, '%Y-%m-%d')
    base_time = int(time.mktime(time_struct.timetuple()))

    rng = MSVCRTRand()

    for length in range(min_length, max_length + 1):
        for second in range(86400):  # 86400 for all the seconds in a day
            time_seed = base_time + second
            rng.srand(time_seed)
            
            # RoboForm generation logic: pick 'length' characters using rand()
            password = ''.join(get_char_from_pool(rng, chars) for _ in range(length))
            passwords.append(password)
            progress.put(password)

    return passwords

def display_progress(progress, total_tasks, min_length, max_length):
    total_passwords = 0
    start_time = time.time()
    while True:
        if progress.empty():
            time.sleep(0.1)
            continue
        password = progress.get()
        if password == "STOP":
            break
        total_passwords += 1
        elapsed_time = time.time() - start_time
        total_bytes = total_passwords * (len(password) + 1)
        total_megabytes = total_bytes / (1024 * 1024)
        total_gigabytes = total_megabytes / 1024
        passwords_per_second = total_passwords / elapsed_time
        remaining_passwords = (total_tasks * (max_length - min_length + 1) * 86400) - total_passwords
        estimated_time_remaining = remaining_passwords / passwords_per_second
        sys.stdout.write(
            f"\rpasswords generated: {total_passwords:,} | size: {total_megabytes:.2f} mb / {total_gigabytes:.2f} gb | "
            f"time remaining: {estimated_time_remaining / 60:.2f} minutes"
        )
        sys.stdout.flush()

def main():
    start_day = input("Enter start date (DD): ")
    start_month = input("Enter start month (MM): ")
    start_year = input("Enter start year (YYYY): ")
    end_day = input("Enter end date (DD): ")
    end_month = input("Enter end month (MM): ")
    end_year = input("Enter end year (YYYY): ")

    min_length = int(input("Enter minimum password length: "))
    max_length = int(input("Enter maximum password length: "))
    include_symbols = input("Include symbols? (y/n): ").lower() == 'y'

    # create datetime objects from user input
    start_date = datetime(int(start_year), int(start_month), int(start_day))
    end_date = datetime(int(end_year), int(end_month), int(end_day))

    num_cores = min(4, cpu_count())  # Limited to 4 cores. You can increase to fit your spec.
    current_date = start_date
    dates = []

    while current_date <= end_date:
        dates.append(current_date.strftime('%Y-%m-%d'))
        current_date += timedelta(days=1)

    total_tasks = len(dates)
    with Manager() as manager:
        progress = manager.Queue()
        tasks = [(date, min_length, max_length, include_symbols, progress) for date in dates]
        pool = Pool(num_cores)
        
        pool.apply_async(display_progress, (progress, total_tasks, min_length, max_length))

        all_passwords = pool.map(generate_passwords_for_day, tasks)
        
        progress.put("STOP")

        with open('robowordlist.txt', 'w') as f:
            for passwords in all_passwords:
                for password in passwords:
                    f.write(password + '\n')

        pool.close()
        pool.join()

    print("\nPassword generation complete.")
    print("Bye")

if __name__ == "__main__":
    main()
