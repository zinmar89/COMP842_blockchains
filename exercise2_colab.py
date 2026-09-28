"""
COMP842 Applied Blockchains and Cryptocurrencies
Exercise 2: Proof of Work - Mining, Difficulty & Probability
Author: Zin Mar Win
"""

import hashlib
import pickle
import statistics
import time

DIFFICULTIES = [2, 3, 4, 5]        # Step 2: difficulty levels to test (leading zeros)
BLOCKS_PER_DIFFICULTY = 30         # Step 3: mine 30 blocks per difficulty level


def sha256(data) -> str:
    return hashlib.sha256(pickle.dumps(data)).hexdigest()


def block_header(index, timestamp, transactions_hash, previous_hash, nonce):
    # The fields that get hashed to produce the block's SHA-256 hash
    return {
        "index": index,
        "timestamp": timestamp,
        "transactions_hash": transactions_hash,
        "previous_hash": previous_hash,
        "nonce": nonce,
    }


# ---------------------------------------------------------------------------
# Step 1: Proof-of-Work mining function
# Keep incrementing the nonce and recalculating the SHA-256 hash until the
# hash begins with `difficulty` leading zeros.
# ---------------------------------------------------------------------------
def mine_block(index, transactions_hash, previous_hash, difficulty, timestamp):
    """Increment nonce until the block's SHA-256 hash starts with `difficulty` hex zeros.
    Returns nonce found, resulting (valid) hash, number of hash attempts, and elapsed time."""
    target_prefix = "0" * difficulty
    nonce = 0
    start = time.perf_counter()
    while True:
        header = block_header(index, timestamp, transactions_hash, previous_hash, nonce)
        h = sha256(header)
        if h.startswith(target_prefix):
            elapsed = time.perf_counter() - start
            return {
                "index": index,
                "difficulty": difficulty,
                "nonce": nonce,
                "hash": h,
                "attempts": nonce + 1,
                "elapsed_seconds": elapsed,
            }
        nonce += 1


if __name__ == "__main__":
    tx_hash = sha256([{"from": "Alice", "to": "Bob", "amount": 10}])
    previous_hash = "0" * 64
    base_timestamp = 1_700_000_000.0

    summary = []

    # -----------------------------------------------------------------
    # Step 2: test each difficulty level (2, 3, 4, 5 leading zeros)
    # -----------------------------------------------------------------
    for difficulty in DIFFICULTIES:
        print("=" * 100)
        print(f"Difficulty {difficulty} (hash must start with '{'0' * difficulty}') "
              f"— mining {BLOCKS_PER_DIFFICULTY} blocks")
        print("=" * 100)

        # -------------------------------------------------------------
        # Step 3: mine 30 blocks at this difficulty, recording the valid
        # hash and number of hash attempts (nonce + 1) for each one
        # -------------------------------------------------------------
        blocks = []
        for i in range(BLOCKS_PER_DIFFICULTY):
            result = mine_block(
                index=i + 1,
                transactions_hash=tx_hash,
                previous_hash=previous_hash,
                difficulty=difficulty,
                timestamp=base_timestamp + i,
            )
            blocks.append(result)
            print(
                f"  Block {i + 1:2d}/{BLOCKS_PER_DIFFICULTY} | nonce={result['nonce']:>9} | "
                f"attempts={result['attempts']:>9,} | time={result['elapsed_seconds']:.4f}s | "
                f"hash={result['hash']}"
            )
            previous_hash = result["hash"]  # chain the next block onto this one

        times = [b["elapsed_seconds"] for b in blocks]
        attempts = [b["attempts"] for b in blocks]

        # -------------------------------------------------------------
        # Step 4: calculate performance metrics for this difficulty level
        # (average/min/max/stdev mining time, mining throughput)
        # -------------------------------------------------------------
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        std_time = statistics.stdev(times)
        avg_attempts = statistics.mean(attempts)
        total_attempts = sum(attempts)
        total_time = sum(times)
        throughput = total_attempts / total_time  # hashes/sec, aggregated across the 30 blocks

        # -------------------------------------------------------------
        # Step 5: theoretical expected hash attempts (~16^difficulty)
        # vs. the measured average number of attempts
        # -------------------------------------------------------------
        theoretical_attempts = 16 ** difficulty

        summary.append({
            "difficulty": difficulty,
            "avg_time": avg_time,
            "min_time": min_time,
            "max_time": max_time,
            "std_time": std_time,
            "avg_attempts": avg_attempts,
            "throughput": throughput,
            "theoretical_attempts": theoretical_attempts,
        })

        print()
        print(f"  Average mining time      : {avg_time:.4f} s")
        print(f"  Minimum mining time      : {min_time:.4f} s")
        print(f"  Maximum mining time      : {max_time:.4f} s")
        print(f"  Std dev of mining time   : {std_time:.4f} s")
        print(f"  Average hash attempts    : {avg_attempts:,.1f}")
        print(f"  Mining throughput        : {throughput:,.0f} hashes/sec")
        print(f"  Theoretical attempts     : {theoretical_attempts:,} (16^{difficulty})")
        print()

    # -----------------------------------------------------------------
    # Step 6: summary table comparing all difficulty levels, including
    # theoretical vs. measured hash attempts
    # -----------------------------------------------------------------
    print("=" * 100)
    print("Summary — all difficulty levels")
    print("=" * 100)
    header = (
        f"{'Diff':<6}{'Avg time (s)':<14}{'Min time (s)':<14}{'Max time (s)':<14}"
        f"{'StdDev (s)':<12}{'Throughput (H/s)':<18}{'Theo. attempts':<16}{'Meas. attempts':<16}"
    )
    print(header)
    print("-" * 100)
    for s in summary:
        print(
            f"{s['difficulty']:<6}{s['avg_time']:<14.4f}{s['min_time']:<14.4f}"
            f"{s['max_time']:<14.4f}{s['std_time']:<12.4f}{s['throughput']:<18,.0f}"
            f"{s['theoretical_attempts']:<16,}{s['avg_attempts']:<16,.1f}"
        )
