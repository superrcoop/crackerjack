"""Unit tests for active cyber deception and honeyword canary tripwires."""

from crackerjack.honey import (
    generate_honeywords,
    inject_honey_hash,
    verify_honeyword,
)


def test_generate_honeywords_basic():
    real = "P@ssw0rd2026!"
    hset = generate_honeywords(real, count=5)

    assert len(hset.honeywords) == 5
    assert hset.decoy_count == 4
    assert hset.real_password == real
    assert hset.real_password in hset.honeywords
    assert hset.honeywords[hset.real_index] == real
    assert hset.canary_tag.startswith("cj-canary-")
    assert hset.avg_entropy_bits > 40.0

    # Ensure decoys are distinct from the real password
    decoys = [w for idx, w in enumerate(hset.honeywords) if idx != hset.real_index]
    assert len(set(decoys)) == 4
    assert real not in decoys


def test_inject_honey_hash_formats():
    # Linux shadow
    shadow_line = inject_honey_hash("shadow", "canary_user", "$2b$12$fakecanaryhash", "canary-tag-1")
    assert "canary_user:$2b$12$fakecanaryhash:19000:0:99999:7:::" in shadow_line
    assert "canary-tag-1" in shadow_line

    # Active Directory NTDS
    ntds_line = inject_honey_hash("ntds", "canary_ad", "31d6cfe0d16ae931b73c59d7e0c089c0", "canary-tag-2")
    assert "canary_ad:9999:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::" in ntds_line
    assert "canary-tag-2" in ntds_line

    # SQL INSERT
    sql_line = inject_honey_hash("sql", "canary_sql", "$2b$12$hash123", "canary-tag-3")
    assert "INSERT INTO users" in sql_line
    assert "is_canary" in sql_line
    assert "canary-tag-3" in sql_line


def test_verify_honeyword_tripwire():
    real = "SecurePass#2026"
    hset = generate_honeywords(real, count=4)

    # 1. Authentic login
    res_auth = verify_honeyword(real, hset)
    assert res_auth["authenticated"] is True
    assert res_auth["tripped_canary"] is False

    # 2. Canary Tripwire tripped!
    decoy = next(w for w in hset.honeywords if w != real)
    res_alarm = verify_honeyword(decoy, hset)
    assert res_alarm["authenticated"] is False
    assert res_alarm["tripped_canary"] is True
    assert res_alarm["incident_level"] == "CRITICAL"
    assert "CRITICAL SECURITY ALARM" in res_alarm["message"]

    # 3. Random incorrect password (not in honeywords)
    res_wrong = verify_honeyword("CompletelyRandomIncorrectWord123!", hset)
    assert res_wrong["authenticated"] is False
    assert res_wrong["tripped_canary"] is False
