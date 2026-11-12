"""JSON <-> Python conversion at the binding boundary (src/convert.rs).

jose-rs 0.10 turns on serde_json's ``arbitrary_precision`` and deserializes
``exp`` / ``iat`` / ``nbf`` from a ``RawValue``; these tests pin the numbers,
dict order and exception types that survive that.
"""

import pytest
from exotic_cases import (
    ACCEPT_CASES,
    BAD_FLOATS,
    BIG_INT_CASES,
    CYCLIC_BUILDERS,
    REJECT_CASES,
    RESERVED_KEY_CASES,
    TOKEN_LOOP_BUILDERS,
    TOKEN_SHAPE_ACCEPT,
    nested,
    wrap_in_lists,
)
from pygrindvakt import federation, jwt


def roundtrip(op_key, claims):
    return jwt.peek_claims_unverified(jwt.sign(op_key, claims))


def test_integers_floats_and_big_ints_roundtrip_as_native_numbers(op_key):
    out = roundtrip(op_key, {"big": 2**70, "neg": -5, "f": 1.5, "i": 7})
    assert out["big"] == 2**70 and type(out["big"]) is int
    assert out["neg"] == -5 and type(out["neg"]) is int
    assert out["i"] == 7 and type(out["i"]) is int
    assert out["f"] == 1.5 and type(out["f"]) is float


@pytest.mark.parametrize("claim", ["exp", "iat", "nbf"])
def test_numeric_date_claims_roundtrip(op_key, claim):
    assert roundtrip(op_key, {claim: 4102444800})[claim] == 4102444800
    assert roundtrip(op_key, {claim: 4102444800.5})[claim] == 4102444800.5


def test_nested_numbers_are_native(op_key):
    out = roundtrip(op_key, {"x": {"a": [1, 2.5, {"b": 3}]}})
    assert out["x"] == {"a": [1, 2.5, {"b": 3}]}


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize("claims", [lambda b: {"x": b}, lambda b: {"exp": b}, lambda b: {"x": [1, {"y": b}]}])
def test_non_finite_numbers_are_refused_not_nulled(op_key, bad, claims):
    with pytest.raises(ValueError, match="non-finite"):
        jwt.sign(op_key, claims(bad))


@pytest.mark.parametrize("bad", BAD_FLOATS)
@pytest.mark.parametrize("case", REJECT_CASES, ids=[c.id for c in REJECT_CASES])
def test_non_finite_in_exotic_containers_refused(op_key, bad, case):
    with pytest.raises(ValueError, match="non-finite"):
        jwt.sign(op_key, {"a": case.build(bad)})
    with pytest.raises(ValueError, match="non-finite"):
        jwt.sign(op_key, {"a": [{"b": case.build(bad)}]})


@pytest.mark.parametrize("case", ACCEPT_CASES, ids=[c.id for c in ACCEPT_CASES])
def test_exotic_containers_signed_exactly(op_key, case):
    assert roundtrip(op_key, {"a": case.build()}) == {"a": case.expected}


def test_depth_limit(op_key):
    # The claims dict is level 1; serde_json's own parser allows 127 levels.
    assert roundtrip(op_key, {"a": nested(126)})["a"] == nested(126)
    with pytest.raises(ValueError, match="nested too deeply"):
        jwt.sign(op_key, {"a": nested(127)})


def test_slots_dataclass_is_pythonize_limitation(op_key):
    # pythonize reads `__dict__`, which slots dataclasses lack; not our guard.
    from exotic_cases import SlotsDC

    with pytest.raises(AttributeError):
        jwt.sign(op_key, {"a": SlotsDC(1.5)})


def test_self_referential_list_refused(op_key):
    loop: list = []
    loop.append(loop)
    with pytest.raises(ValueError, match="nested too deeply"):
        jwt.sign(op_key, {"a": loop})


@pytest.mark.parametrize("name", sorted(CYCLIC_BUILDERS))
def test_cyclic_or_deep_non_list_container_refused(op_key, name):
    with pytest.raises(ValueError, match="nested too deeply"):
        jwt.sign(op_key, {"a": CYCLIC_BUILDERS[name]()})


@pytest.mark.parametrize("name", sorted(TOKEN_LOOP_BUILDERS))
def test_cyclic_or_chained_token_map_refused_without_recursing(op_key, name):
    with pytest.raises(ValueError, match="reserved"):
        jwt.sign(op_key, {"a": TOKEN_LOOP_BUILDERS[name]()})


@pytest.mark.parametrize("leaf", [1, 2**128, -(2**200), 10**400])
def test_big_int_counts_like_any_scalar_at_the_depth_limit(op_key, leaf):
    # The claims dict is level 1, so 126 lists is the deepest accepted nesting
    # for a scalar and 127 is refused: a big int (pythonize's token map) must
    # land on the same boundary as the plain `1`.
    ok = wrap_in_lists(leaf, 126)
    out = roundtrip(op_key, {"a": ok})["a"]
    for _ in range(126):
        out = out[0]
    assert out == leaf
    with pytest.raises(ValueError, match="nested too deeply"):
        jwt.sign(op_key, {"a": wrap_in_lists(leaf, 127)})


def test_very_deep_list_refused(op_key):
    with pytest.raises(ValueError, match="nested too deeply"):
        jwt.sign(op_key, {"a": nested(10_000)})


def test_huge_ints_stay_exact(op_key):
    for n in (2**64, 2**200, -(2**70)):
        assert roundtrip(op_key, {"x": n})["x"] == n


def test_wrong_shape_is_type_error():
    with pytest.raises(TypeError):
        federation.apply_policy(["not", "a", "dict"], {})


@pytest.mark.parametrize("case", RESERVED_KEY_CASES, ids=[c.id for c in RESERVED_KEY_CASES])
def test_reserved_number_key_refused(op_key, case):
    for claims in ({"a": case.value}, {"a": [{"b": case.value}]}, {"a": {"b": case.value}}):
        with pytest.raises(ValueError, match="reserved"):
            jwt.sign(op_key, claims)


@pytest.mark.parametrize(("n", "digits"), BIG_INT_CASES)
def test_big_ints_exact_digits(op_key, n, digits):
    import base64

    token = jwt.sign(op_key, {"x": n})
    payload = base64.urlsafe_b64decode(token.split(".")[1] + "==")
    assert f'"x":{digits}'.encode() in payload
    assert roundtrip(op_key, {"x": n})["x"] == n


def test_int_over_str_digit_limit_has_clear_error(op_key, unraisable):
    # pyo3 reports the refused int-to-str conversion through sys.unraisablehook.
    import sys

    old = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4300)
        assert roundtrip(op_key, {"x": 10**4299})["x"] == 10**4299
        with pytest.raises(ValueError, match="too many digits"):
            jwt.sign(op_key, {"x": 10**4400})

        class Big(int):
            pass

        with pytest.raises(ValueError, match="too many digits"):
            jwt.sign(op_key, {"x": Big(10**4400)})
        unraisable.expect(ValueError, "Exceeds the limit", count=2)
    finally:
        sys.set_int_max_str_digits(old)


def test_int_over_default_digit_limit_exact_when_limit_raised(op_key):
    import sys

    old = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(0)
        n = 10**5000
        assert roundtrip(op_key, {"x": n})["x"] == n
    finally:
        sys.set_int_max_str_digits(old)


def test_decimal_is_type_error(op_key):
    import decimal

    with pytest.raises(TypeError):
        jwt.sign(op_key, {"x": decimal.Decimal("1.5")})


@pytest.mark.parametrize(("token", "digits"), TOKEN_SHAPE_ACCEPT)
def test_token_shaped_dict_is_the_integer_it_encodes(op_key, token, digits):
    # Documented limit: a dict with exactly pythonize's big-int token shape is that int.
    assert roundtrip(op_key, {"x": token})["x"] == int(digits)


def test_token_shaped_digit_string_obeys_int_digit_limit(op_key):
    import sys

    from exotic_cases import TOKEN

    old = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(4300)
        assert roundtrip(op_key, {"x": {TOKEN: "9" * 4300}})["x"] == int("9" * 4300)
        for n in (4301, 100_001):
            with pytest.raises(ValueError, match="too many digits"):
                jwt.sign(op_key, {"x": {TOKEN: "9" * n}})
        sys.set_int_max_str_digits(0)  # unlimited, as for a real int
        assert roundtrip(op_key, {"x": {TOKEN: "9" * 5000}})["x"] == int("9" * 5000)
    finally:
        sys.set_int_max_str_digits(old)
