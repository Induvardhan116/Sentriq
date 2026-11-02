import logging
from typing import Optional
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger("sentriq.security.hasher")

# OWASP Recommended Argon2id parameters
# memory_cost=65536 (64 MiB), time_cost=3 iterations, parallelism=4 threads
_argon2_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Precomputed dummy hash used to prevent timing attacks on non-existent users
_DUMMY_ARGON2_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$2wE/VtY/0G7dBWLDhenoDw$7hx3QkVCAVq4/yuWXFWKKaCLQXJCRjHg4V9j9XfX5JM"
)


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    if not plain_password or not isinstance(plain_password, str):
        raise ValueError("Password must be a non-empty string.")
    return _argon2_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    """Verify a plaintext password against an Argon2id hash in constant time."""
    if not plain_password or not hashed_password:
        return False

    try:
        return _argon2_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as e:
        logger.warning("Unexpected error during password verification: %s", e)
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Determine if a stored hash requires re-hashing due to upgraded parameters."""
    if not hashed_password:
        return True
    try:
        return _argon2_hasher.check_needs_rehash(hashed_password)
    except Exception:
        return True


def dummy_verify() -> None:
    """Perform a constant-time dummy verification when user is not found.

    Prevents user enumeration attacks by matching the CPU time of real password verification.
    """
    try:
        _argon2_hasher.verify(_DUMMY_ARGON2_HASH, "incorrect-candidate-password")
    except Exception:
        pass
