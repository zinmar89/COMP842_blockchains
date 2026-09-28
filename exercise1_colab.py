"""
COMP842 Applied Blockchains and Cryptocurrencies
Exercise 1: Blockchain Structure and Tamper Detection
Author: Zin Mar Win
"""

import hashlib
import pickle
import time


# ---------------------------------------------------------------------------
# Step 2: SHA-256 hash helper (hashes pickled bytes)
# ---------------------------------------------------------------------------
def sha256(data) -> str:
    return hashlib.sha256(pickle.dumps(data)).hexdigest()


# ---------------------------------------------------------------------------
# Step 1: Design and create a "Block" class
# ---------------------------------------------------------------------------
class Block:
    def __init__(self, transactions, prev_hash, timestamp=None, nonce=0):
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.transactions = transactions
        self.prev_hash = prev_hash
        self.nonce = nonce

        # Step 3: Merkle root over the block's transactions, computed at
        # construction time and stored on the block.
        self.merkle_root = self.compute_merkle_root(self.transactions)

        # Step 2: SHA-256 hash of the block's contents (uses the Merkle
        # root rather than the raw transaction list).
        self.hash = self.calculate_hash()

    # -----------------------------------------------------------------
    # Step 3: Merkle root computation
    # -----------------------------------------------------------------
    @staticmethod
    def compute_merkle_root(transactions):
        if not transactions:
            return sha256("")

        # Leaf level: one SHA-256 hash per transaction (pickled)
        layer = [sha256(tx) for tx in transactions]

        # Pair up and hash each level until a single root hash remains
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])  # duplicate last hash on odd count
            layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]

        return layer[0]

    # -----------------------------------------------------------------
    # Step 2: Block hash computation (SHA-256, pickled contents)
    # -----------------------------------------------------------------
    def calculate_hash(self):
        block_contents = {
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
        }
        return sha256(block_contents)

    def __repr__(self):
        return (
            f"Block(hash={self.hash[:12]}..., "
            f"prev={self.prev_hash[:12]}..., merkle={self.merkle_root[:12]}..., "
            f"tx_count={len(self.transactions)})"
        )


# ---------------------------------------------------------------------------
# Step 1: Design and create a "Blockchain" class
# ---------------------------------------------------------------------------
class Blockchain:
    def __init__(self):
        self.chain = []
        # Step 2: automatically create a genesis block on initialisation
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(transactions=["Genesis Block"], prev_hash="0" * 64)
        self.chain.append(genesis_block)

    def get_latest_block(self):
        return self.chain[-1]

    # -----------------------------------------------------------------
    # Step 3: allow new blocks to be appended
    # -----------------------------------------------------------------
    def add_block(self, transactions):
        previous_block = self.get_latest_block()
        new_block = Block(transactions=transactions, prev_hash=previous_block.hash)
        self.chain.append(new_block)
        return new_block

    # -----------------------------------------------------------------
    # Step 4 & 5: validate the whole chain, reporting the first block
    # that fails validation
    # -----------------------------------------------------------------
    def is_chain_valid(self):
        for position, current in enumerate(self.chain):
            if current.merkle_root != Block.compute_merkle_root(current.transactions):
                return False, position, "Merkle root does not match transaction data"

            if current.hash != current.calculate_hash():
                return False, position, "Block hash does not match recalculated hash"

            if position > 0 and current.prev_hash != self.chain[position - 1].hash:
                return False, position, "prev_hash does not match previous block's hash"

        return True, None, None


def print_chain(blockchain):
    for position, block in enumerate(blockchain.chain):
        print(f"Block {position}")
        print(f"  Timestamp     : {block.timestamp}")
        print(f"  Transactions  : {block.transactions}")
        print(f"  Merkle Root   : {block.merkle_root}")
        print(f"  Prev Hash     : {block.prev_hash}")
        print(f"  Hash          : {block.hash}")
        print()


# ---------------------------------------------------------------------------
# Step 6: create a blockchain containing 10 blocks (including the genesis
# block), each with different transaction data
# ---------------------------------------------------------------------------
blockchain = Blockchain()

sample_transactions = [
    ["A", "B", "C"],
    ["D", "E"],
    ["F", "G", "H", "I"],
    ["J"],
    ["K", "L"],
    ["M", "N", "O"],
    ["P", "Q"],
    ["R", "S", "T"],
    ["U", "V"],
]

for tx_set in sample_transactions:
    blockchain.add_block(tx_set)

print("=" * 70)
print(f"Blockchain created with {len(blockchain.chain)} blocks (including genesis)")
print("=" * 70)
print_chain(blockchain)

is_valid, bad_position, reason = blockchain.is_chain_valid()
print(f"Validation BEFORE tampering -> valid: {is_valid}")
print()

# ---------------------------------------------------------------------------
# Step 7 & 8: modify the transaction data in the 5th block (position 4)
# WITHOUT recalculating its hash or Merkle root
# ---------------------------------------------------------------------------
tampered_block = blockchain.chain[4]
print("Tampering with Block 4 (the 5th block in the chain)...")
print(f"  Original transactions: {tampered_block.transactions}")
tampered_block.transactions = ["Mallory-fraud-tx"]
print(f"  Tampered transactions : {tampered_block.transactions}")
print("  (hash and merkle_root left untouched)")
print()

# ---------------------------------------------------------------------------
# Step 9: validate the tampered blockchain and report the result
# ---------------------------------------------------------------------------
is_valid, bad_position, reason = blockchain.is_chain_valid()
print("=" * 70)
print("Validation AFTER tampering with Block 4 (5th block)")
print("=" * 70)
print(f"Chain valid         : {is_valid}")
print(f"First failing block : {bad_position}")
print(f"Reason              : {reason}")
