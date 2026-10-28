import os
import stat
import pytest
from y2q.hndl.attack import run_hndl_attack
from y2q.hndl.prepare import generate_case


def test_attack_succeeds_without_truth_file(tmp_path):
    """Assert attack cannot read truth.json: runs when truth.json is completely absent."""
    case_dir = tmp_path / "case_absent_truth"
    challenge_file, truth_file = generate_case(case_dir, private_scalar_a=7, private_scalar_b=11)

    # Delete truth.json completely
    truth_file.unlink()
    assert not truth_file.exists()

    # Attack must succeed from challenge.json alone
    res = run_hndl_attack(challenge_file, backend="simulator", shots=4096, artifacts_dir=tmp_path / "artifacts")
    assert res["status"] == "SUCCESS"
    assert res["candidate_status"] == "RECOVERED"
    assert res["candidate_k"] == 7
    assert res["public_relation_status"] == "VERIFIED"
    assert res["decrypted"] is True
    assert res["sha256_match"] is True


def test_attack_succeeds_when_truth_file_unreadable(tmp_path):
    """Assert attack does not attempt to read truth.json even if chmod 000."""
    case_dir = tmp_path / "case_unreadable_truth"
    challenge_file, truth_file = generate_case(case_dir, private_scalar_a=13, private_scalar_b=5)

    # Make truth.json unreadable (chmod 000)
    try:
        truth_file.chmod(0o000)
    except Exception:
        pass

    res = run_hndl_attack(challenge_file, backend="simulator", shots=4096, artifacts_dir=tmp_path / "artifacts")
    assert res["status"] == "SUCCESS"
    assert res["candidate_k"] == 13
    assert res["decrypted"] is True
    assert res["sha256_match"] is True

    # Restore permission for clean tmp_path teardown on Windows
    try:
        truth_file.chmod(stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass
