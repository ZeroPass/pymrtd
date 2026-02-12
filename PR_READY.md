# Pull Request Ready

This file indicates that the branch `add-ecc-tests-cryptography-46-init` is ready for PR creation.

## Changes Made

1. Modified `src/pymrtd/pki/keys.py`:
   - Added logging import
   - Restructured monkey patch block to use try/except/else pattern
   - Changed bare except to `except Exception`
   - Added logging for when internals are available/not available
   - Applied monkey patch in else block with info logging

2. Created `tests/test_ecc_verification.py`:
   - Added test_ec_verify_x962_signature() - tests ECDSA verification with X9.62 (DER) signature
   - Added test_ec_verify_plain_signature() - tests ECDSA verification with plain (r||s) signature
   - Both tests generate EC SECP256R1 keypair and sign/verify messages

## Test Results

Both tests pass:
- test_ec_verify_x962_signature PASSED
- test_ec_verify_plain_signature PASSED

## PR Details

- **Branch**: add-ecc-tests-cryptography-46-init
- **Base**: dependabot/pip/cryptography-46.0.5
- **Title**: Guard cryptography internals import; add ECC verification tests (init commit)
- **Body**: See below

---

**PR Body:**

This PR makes `src/pymrtd/pki/keys.py` resilient to cryptography internal API removal (cryptography >=46) by guarding the internal import and applying the monkey patch only when internals exist.

## Changes

1. **Modified src/pymrtd/pki/keys.py**:
   - Added logging support to track monkey patch application
   - Restructured internal cryptography API import to use try/except/else pattern
   - Replaced bare `except` with `except Exception` for better exception handling
   - Added debug/info logging to indicate whether monkey patch was applied or skipped

2. **Added tests/test_ecc_verification.py**:
   - Implemented ECC verification tests exercising ECDSA verification
   - Tests cover both X9.62 (DER) signatures and plain (r||s) signatures
   - Uses generated EC SECP256R1 keys for testing

## Notes

- CI/workflow files were intentionally left unchanged per requirements
- Tests pass successfully with cryptography 46.0.5
- The monkey patch gracefully falls back when internal APIs are not available
