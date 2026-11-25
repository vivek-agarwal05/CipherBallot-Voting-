"""
app/security/canonical.py — Deterministic JSON serialisation.

Canonical JSON is used wherever a byte-stable representation of a dict is
required for cryptographic operations (hashing, signing, AAD construction).

Rules:
  - Keys sorted lexicographically (sort_keys=True)
  - No extra whitespace (compact separators)
  - UTF-8 encoded (no ASCII escaping of non-ASCII chars)
"""
import json


def canonical_json(data: dict) -> bytes:
    """
    Return a deterministic, compact UTF-8 JSON encoding of *data*.

    The output is stable across Python versions and platforms for the same
    logical dict, making it safe to use as input to hash and sign operations.

    >>> canonical_json({'b': 2, 'a': 1}) == b'{"a":1,"b":2}'
    True
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')
