"""Response-similarity clustering to collapse near-identical pages.

Extends reNgine's existing exact content-length/title dedup
(reNgine/tasks.py:remove_duplicate_endpoints) with a fuzzy signature so pages
that differ only trivially (CSRF token, timestamp) group together instead of
counting as distinct attack surface. Pure Python, no external deps.
"""

import re


def normalize(text):
    """Lowercase, strip tags/whitespace/digits so trivial differences vanish."""
    if not text:
        return ''
    text = re.sub(r'<[^>]+>', ' ', text)         # drop HTML tags
    text = re.sub(r'\d+', '', text)               # drop numbers (ids/timestamps)
    text = re.sub(r'\s+', ' ', text).strip().lower()
    return text


def simhash(text, bits=64):
    """Compute a 64-bit simhash of the normalized text's token shingles."""
    text = normalize(text)
    if not text:
        return 0
    tokens = text.split()
    shingles = [' '.join(tokens[i:i + 3]) for i in range(len(tokens))] or tokens
    vector = [0] * bits
    for sh in shingles:
        h = _hash(sh) % (1 << bits)
        for i in range(bits):
            vector[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if vector[i] > 0:
            out |= (1 << i)
    return out


def hamming_distance(a, b):
    return bin(a ^ b).count('1')


def is_similar(a_hash, b_hash, threshold=3):
    """Two simhashes are 'the same page' if within `threshold` bits."""
    return hamming_distance(a_hash, b_hash) <= threshold


def cluster(items, threshold=3):
    """Greedy clustering of (id, text) pairs by simhash similarity.

    Returns list of clusters, each a list of ids; first id is the representative.
    """
    hashed = [(item_id, simhash(text)) for item_id, text in items]
    clusters = []
    reps = []  # (rep_hash,)
    for item_id, h in hashed:
        placed = False
        for idx, rep_hash in enumerate(reps):
            if is_similar(h, rep_hash, threshold):
                clusters[idx].append(item_id)
                placed = True
                break
        if not placed:
            reps.append(h)
            clusters.append([item_id])
    return clusters


def _hash(s):
    """Stable non-crypto hash for a string (independent of PYTHONHASHSEED)."""
    h = 1469598103934665603
    for ch in s.encode('utf-8'):
        h ^= ch
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h
