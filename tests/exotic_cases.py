"""Exotic containers shared by the NaN/infinity tests of ``jwt.sign`` and
``ReqwestClient.post_json`` (both go through ``convert::from_py``).

``REJECT_CASES`` hold one float that must be refused when non-finite; each
carries the EXACT value expected on the wire when that float is ``1.5``.
``ACCEPT_CASES`` are finite (or non-field) data that must be converted exactly
as pythonize reads them.
"""

from __future__ import annotations

import collections
import dataclasses
import types
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Callable

BAD_FLOATS = [float("nan"), float("inf"), float("-inf")]


@dataclasses.dataclass
class DC:
    v: float


@dataclasses.dataclass(slots=True)
class SlotsDC:
    v: float


class ValuesOverride(dict):  # type: ignore[type-arg]
    """pythonize reads ``values()``, not the raw storage."""

    def __init__(self, x: Any) -> None:
        super().__init__({"a": 0})
        self._x = x

    def values(self) -> Any:  # type: ignore[override]
        return [self._x]


class GetItemList(list):  # type: ignore[type-arg]
    def __init__(self, x: Any) -> None:
        super().__init__([0])
        self._x = x

    def __getitem__(self, i: Any) -> Any:
        return self._x


class GetItemTuple(tuple):  # type: ignore[type-arg]
    def __new__(cls, x: Any) -> GetItemTuple:  # noqa: PYI034
        obj = super().__new__(cls, (0,))
        obj._x = x  # type: ignore[attr-defined]
        return obj

    def __getitem__(self, i: Any) -> Any:
        return self._x  # type: ignore[attr-defined]


class KeysValuesOverride(dict):  # type: ignore[type-arg]
    """Raw storage {"a": nan}; overridden accessors present finite {"z": 1}."""

    def keys(self) -> Any:  # type: ignore[override]
        return ["z"]

    def values(self) -> Any:  # type: ignore[override]
        return [1]


class Case(NamedTuple):
    id: str
    build: Callable[[float], Any]
    expected: Any  # exact JSON value for build(1.5)


REJECT_CASES = [
    Case("set", lambda x: {x}, [1.5]),
    Case("frozenset", lambda x: frozenset([x]), [1.5]),
    Case("deque", lambda x: collections.deque([x]), [1.5]),
    Case("UserList", lambda x: collections.UserList([x]), [1.5]),
    Case("UserDict", lambda x: collections.UserDict({"k": x}), {"k": 1.5}),
    Case("mappingproxy", lambda x: types.MappingProxyType({"k": x}), {"k": 1.5}),
    Case("dataclass", lambda x: DC(x), {"v": 1.5}),
    Case("dict_values_override", lambda x: ValuesOverride(x), {"a": 1.5}),
    Case("list_getitem_override", lambda x: GetItemList(x), [1.5]),
    Case("tuple_getitem_override", lambda x: GetItemTuple(x), [1.5]),
]


def _dataclass_extra_attr() -> Any:
    obj = DC(1.5)
    obj.extra = float("nan")  # type: ignore[attr-defined]
    return obj


def _keys_values_override() -> Any:
    return KeysValuesOverride({"a": float("nan")})


class Accept(NamedTuple):
    id: str
    build: Callable[[], Any]
    expected: Any


ACCEPT_CASES = [Accept(c.id, (lambda c=c: c.build(1.5)), c.expected) for c in REJECT_CASES] + [
    # Only dataclass fields are sent; a NaN in a non-field attribute is not.
    Accept("dataclass_non_field_nan", _dataclass_extra_attr, {"v": 1.5}),
    # pythonize reads through the overridden accessors, so the raw NaN is unseen.
    Accept("keys_values_override_finite", _keys_values_override, {"z": 1}),
    Accept("large_deque", lambda: collections.deque(range(100_000)), list(range(100_000))),
]


def nested(depth: int) -> list[Any]:
    """``depth`` nested lists (the innermost empty)."""
    obj: list[Any] = []
    for _ in range(depth - 1):
        obj = [obj]
    return obj


TOKEN = "$serde_json::private::Number"


class ReservedCase(NamedTuple):
    id: str
    value: Any


# User dicts abusing the reserved big-int key; each must raise ValueError.
RESERVED_KEY_CASES = [
    ReservedCase("overflow_float", {TOKEN: "1e999"}),
    ReservedCase("small_int", {TOKEN: "99"}),
    ReservedCase("extra_entries_nan", {TOKEN: "1", "y": {"z": float("nan")}}),
    ReservedCase("unparsable", {TOKEN: "abc"}),
    ReservedCase("non_string", {TOKEN: 5}),
    ReservedCase("not_first", {"y": 1, TOKEN: "1"}),
]

# The token shape pythonize emits for a real big int is indistinguishable from a
# user dict of the same shape, so that shape is accepted as the integer (up to the
# interpreter's digit limit): (dict, expected wire digits).
TOKEN_SHAPE_ACCEPT = [
    ({TOKEN: "9" * 39}, "9" * 39),
    ({TOKEN: str(2**128)}, str(2**128)),
    ({TOKEN: "-" + "9" * 39}, "-" + "9" * 39),
]

# Genuine big ints must keep exact digits: (value, expected wire digits).
BIG_INT_CASES = [
    (10**400, "1" + "0" * 400),
    (-(2**200), str(-(2**200))),
    (2**70, str(2**70)),
    (-(2**64), str(-(2**64))),
]


def _cyc_deque():
    a: collections.deque = collections.deque()
    a.append(a)
    return a


def _cyc_userlist():
    a = collections.UserList()
    a.append(a)
    return a


def _cyc_userdict():
    a = collections.UserDict()
    a["k"] = a
    return a


def _cyc_dict_in_deque():
    d: dict = {}
    q = collections.deque([d])
    d["q"] = q
    return q


def _deep_deque():
    a: collections.deque = collections.deque()
    for _ in range(50_000):
        a = collections.deque([a])
    return a


_TOKEN = "$serde_json::private::Number"


def _token_cycle():
    d: dict = {}
    d[_TOKEN] = d
    return d


def _token_chain():
    obj: object = "leaf"
    for _ in range(200_000):
        obj = {_TOKEN: obj}
    return obj


# Cycles and absurd depth through non-list containers must raise ValueError,
# never overflow the stack (a SIGSEGV would kill the interpreter).
CYCLIC_BUILDERS = {
    "deque": _cyc_deque,
    "userlist": _cyc_userlist,
    "userdict": _cyc_userdict,
    "dict_in_deque": _cyc_dict_in_deque,
    "deep_deque": _deep_deque,
    "token_cycle": _token_cycle,
    "token_chain": _token_chain,
}
