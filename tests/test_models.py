from core.layout import assemble
from protocols.registry import PROTOCOLS

import pytest


def all_cases(seed=0, n=10_000):
    for info in PROTOCOLS.values():
        yield info, list(info.model(seed=seed).generate_cases(n))


def test_models_generate_cases():
    for info, cases in all_cases():
        assert cases, info.id
        for case in cases:
            assert case.payloads
            assert case.layer == info.layer
            assert case.protocol == info.id


def test_same_seed_same_bytes_and_different_seed_differs_for_tls():
    a = [c.payloads for c in PROTOCOLS["tls-clienthello-like"].model(seed=1).generate_cases(99)]
    b = [c.payloads for c in PROTOCOLS["tls-clienthello-like"].model(seed=1).generate_cases(99)]
    c = [c.payloads for c in PROTOCOLS["tls-clienthello-like"].model(seed=2).generate_cases(99)]
    assert a == b
    assert a != c


def test_layouts_cover_payloads_exactly():
    for info, cases in all_cases():
        for case in cases:
            md = case.metadata
            assert len(md["layouts"]) == len(case.payloads) == len(md["mutated"])
            for payload, layout, mutated in zip(case.payloads, md["layouts"], md["mutated"]):
                assert sum(f["length"] for f in layout) == len(payload)
                assert all(m in {f["name"] for f in layout} for m in mutated)
                pos = 0
                for f in layout:
                    assert f["start"] == pos
                    pos += f["length"]


def test_case_names_are_unique_and_stable_across_max_cases():
    for info in PROTOCOLS.values():
        full = {c.name: c.payloads for c in info.model(seed=5).generate_cases(10_000)}
        assert len(full) == len(list(info.model(seed=5).generate_cases(10_000)))
        small = list(info.model(seed=5).generate_cases(3))
        assert len(small) == 3
        for case in small:  # a case keeps its name and bytes whatever max_cases is
            assert full[case.name] == case.payloads


def test_selection_spreads_across_the_whole_list():
    cases = list(PROTOCOLS["generic-tlv"].model().generate_cases(20))
    assert len(cases) == 20
    assert len({c.metadata["size"] for c in cases}) > 3  # not just the first few seed values


def test_ipv4_checksums_are_valid_unless_mutated():
    for case in PROTOCOLS["ipv4-icmp"].model().generate_cases(99):
        pkt = case.payloads[0]
        from protocols.network.ipv4_icmp import internet_checksum
        header_ok = internet_checksum(pkt[:20]) == 0
        assert header_ok == ("header_checksum" not in case.metadata["mutated"][0])
        assert internet_checksum(pkt[20:]) == 0


def test_assemble_rejects_unknown_mutated_field():
    with pytest.raises(ValueError):
        assemble([("a", b"\x00")], mutated=["nope"])
