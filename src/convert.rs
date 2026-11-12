//! Shared helpers for the binding: submodule creation, warnings, JSON <-> Python
//! conversion, and the fail-closed plumbing used by the Python protocol adapters.

use pyo3::exceptions::{PyTypeError, PyUserWarning, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::fmt;

/// Emit a Python `UserWarning` from Rust on a best-effort basis (it never raises
/// back into Rust). Used to flag security downgrades so they cannot be turned on
/// silently.
pub fn warn(py: Python<'_>, message: &str) {
    if let Ok(warnings) = py.import("warnings") {
        let category = py.get_type::<PyUserWarning>();
        let _ = warnings.call_method1("warn", (message, category));
    }
}

/// Create a child submodule, register it under the parent, and insert it into
/// `sys.modules` as `pygrindvakt.<name>` so both `import pygrindvakt.<name>` and
/// attribute access work.
pub fn new_submodule<'py>(
    py: Python<'py>,
    parent: &Bound<'py, PyModule>,
    name: &str,
) -> PyResult<Bound<'py, PyModule>> {
    let child = PyModule::new(py, name)?;
    let qualified = format!("pygrindvakt.{name}");
    child.setattr("__name__", &qualified)?;
    parent.add(name, &child)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item(&qualified, &child)?;
    Ok(child)
}

/// Serialize any `serde::Serialize` value into native Python objects
/// (dict / list / str / int / float / bool / None).
pub fn to_py<'py, T: Serialize + ?Sized>(
    py: Python<'py>,
    value: &T,
) -> PyResult<Bound<'py, PyAny>> {
    // Via `Value`: types holding a `RawValue` (jose-rs `NumericDate`) only
    // serialize correctly through serde_json.
    let value = serde_json::to_value(value).map_err(|e| PyValueError::new_err(e.to_string()))?;
    pythonize::pythonize(py, &value).map_err(PyErr::from)
}

/// Containers may nest at most this deep. serde_json's parser (used for the
/// text round trip below) allows 127 levels and fails on the 128th with a
/// "recursion limit exceeded" error, so cap there for a uniform message.
const MAX_JSON_DEPTH: usize = 127;

/// Key serde_json (`arbitrary_precision`) and pythonize use to hand a number
/// that does not fit a native integer through `visit_map`.
const NUMBER_TOKEN: &str = "$serde_json::private::Number";

const NON_FINITE_MSG: &str = "non-finite number (NaN or infinity) is not valid JSON";
const TOO_DEEP_MSG: &str = "value is nested too deeply";
const INT_TOO_LARGE_MSG: &str =
    "integer has too many digits to convert to JSON (see sys.set_int_max_str_digits)";
const RESERVED_KEY_MSG: &str =
    "dict key '$serde_json::private::Number' is reserved and cannot be used in JSON data";

/// A `serde_json::Value` deserializer seed that mirrors `Value`'s own visitor
/// but refuses what `Value` would silently alter or cannot bound:
///
/// * NaN / infinity (`Value` turns them into `null`, so `{"exp": nan}` would
///   sign as `{"exp": null}`);
/// * nesting beyond [`MAX_JSON_DEPTH`] (also stops self-referential input
///   before pythonize recurses far).
///
/// Because it sees exactly the values pythonize hands to serde, it cannot
/// disagree with pythonize about what is read from a container.
struct CheckedSeed<'a> {
    depth: usize,
    /// `sys.get_int_max_str_digits()` (0 = unlimited): the largest integer
    /// token accepted, so a digit string cannot get past the limit a real
    /// Python int is held to.
    max_digits: usize,
    /// Set when we reject; pythonize turns custom errors into a bare
    /// `Exception`, so `from_py` uses this to raise `ValueError` instead.
    rejected: &'a Cell<Option<&'static str>>,
}

impl<'a> CheckedSeed<'a> {
    fn reject<E: de::Error>(&self, msg: &'static str) -> E {
        self.rejected.set(Some(msg));
        E::custom(msg)
    }

    fn child(&self) -> Self {
        CheckedSeed {
            depth: self.depth + 1,
            max_digits: self.max_digits,
            rejected: self.rejected,
        }
    }
}

impl<'de> de::DeserializeSeed<'de> for CheckedSeed<'_> {
    type Value = serde_json::Value;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> de::Visitor<'de> for CheckedSeed<'_> {
    type Value = serde_json::Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(v.into()))
    }

    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Self::Value, E> {
        serde_json::Number::deserialize(de::value::I128Deserializer::new(v))
            .map(serde_json::Value::Number)
    }

    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Self::Value, E> {
        serde_json::Number::deserialize(de::value::U128Deserializer::new(v))
            .map(serde_json::Value::Number)
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(v)
            .map(serde_json::Value::Number)
            .ok_or_else(|| self.reject(NON_FINITE_MSG))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(self.reject(TOO_DEEP_MSG));
        }
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(self.child())? {
            out.push(v);
        }
        Ok(serde_json::Value::Array(out))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        // Before any descent, including the big-integer token branch below:
        // a chain of token maps must not recurse without bound.
        if self.depth >= MAX_JSON_DEPTH {
            return Err(self.reject(TOO_DEEP_MSG));
        }
        let Some(first) = map.next_key::<String>()? else {
            return Ok(serde_json::Value::Object(serde_json::Map::new()));
        };
        if first == NUMBER_TOKEN {
            // pythonize emits a big integer as exactly this one entry, mapped to
            // its digit string (and only for values outside i128 / u128). Anything
            // else using the key is user data that `Value` would collapse into a
            // number, so refuse it. A user dict with exactly this shape (one
            // entry, a canonical digit string beyond 128 bits, within the int
            // digit limit) cannot be told apart from a real big int: pythonize
            // offers no discriminator, so it is accepted as that integer.
            let value = map.next_value_seed(self.child())?;
            let serde_json::Value::String(digits) = value else {
                return Err(self.reject(RESERVED_KEY_MSG));
            };
            if map.next_key::<String>()?.is_some() {
                return Err(self.reject(RESERVED_KEY_MSG));
            }
            // pyo3 renders an int that CPython refuses to stringify (over
            // `sys.get_int_max_str_digits()`) as `<unprintable {type} object>`,
            // where {type} is the class name (so also for int subclasses).
            if digits.starts_with("<unprintable ") && digits.ends_with(" object>") {
                return Err(self.reject(INT_TOO_LARGE_MSG));
            }
            let integer_form = digits.strip_prefix('-').unwrap_or(&digits);
            let is_big = !integer_form.is_empty()
                && integer_form.bytes().all(|b| b.is_ascii_digit())
                && digits.parse::<i128>().is_err()
                && digits.parse::<u128>().is_err();
            if !is_big {
                return Err(self.reject(RESERVED_KEY_MSG));
            }
            if self.max_digits > 0 && integer_form.len() > self.max_digits {
                return Err(self.reject(INT_TOO_LARGE_MSG));
            }
            return serde_json::from_str::<serde_json::Number>(&digits)
                .map(serde_json::Value::Number)
                .map_err(|_| self.reject(RESERVED_KEY_MSG));
        }
        let mut out = serde_json::Map::new();
        out.insert(first, map.next_value_seed(self.child())?);
        while let Some(key) = map.next_key::<String>()? {
            if key == NUMBER_TOKEN {
                return Err(self.reject(RESERVED_KEY_MSG));
            }
            out.insert(key, map.next_value_seed(self.child())?);
        }
        Ok(serde_json::Value::Object(out))
    }
}

/// Deserialize native Python objects into any `serde::Deserialize` type.
///
/// NaN / infinity anywhere in the data pythonize reads, and nesting deeper
/// than [`MAX_JSON_DEPTH`], raise `ValueError`.
pub fn from_py<T: DeserializeOwned>(obj: &Bound<'_, PyAny>) -> PyResult<T> {
    let rejected = Cell::new(None);
    // 4300 is CPython's default if the interpreter cannot be asked.
    let max_digits = obj
        .py()
        .import("sys")
        .and_then(|m| m.call_method0("get_int_max_str_digits"))
        .and_then(|v| v.extract::<usize>())
        .unwrap_or(4300);
    let seed = CheckedSeed {
        depth: 0,
        max_digits,
        rejected: &rejected,
    };
    let value =
        de::DeserializeSeed::deserialize(seed, &mut pythonize::Depythonizer::from_object(obj))
            .map_err(|e| match rejected.get() {
                Some(msg) => PyValueError::new_err(msg),
                // bytes reach serde as `invalid type: byte array`, which
                // pythonize surfaces as a bare `Exception`: it is a wrong
                // type, not an internal error.
                None if e.to_string().starts_with("invalid type:") => {
                    PyTypeError::new_err(e.to_string())
                }
                None => PyErr::from(e),
            })?;
    // Via JSON text: jose-rs `NumericDate` deserializes from a `RawValue`,
    // which only serde_json's own deserializer can supply.
    let text = serde_json::to_string(&value).map_err(|e| PyValueError::new_err(e.to_string()))?;
    // A shape mismatch stays a `TypeError`, as with direct depythonize.
    serde_json::from_str(&text).map_err(|e| {
        if e.is_data() {
            PyTypeError::new_err(e.to_string())
        } else {
            PyValueError::new_err(e.to_string())
        }
    })
}

/// Convert convenience request data into ordered form/query pairs.
///
/// Mappings remain accepted here for the non-protocol convenience fields on
/// `HttpRequestData`. Security-sensitive parser entry points must instead use
/// [`protocol_parameter_pairs`], which rejects mappings.
pub fn parameter_pairs(obj: &Bound<'_, PyAny>, name: &str) -> PyResult<Vec<(String, String)>> {
    if let Ok(mapping) = obj.cast::<PyDict>() {
        return mapping
            .iter()
            .map(|(key, value)| Ok((key.extract()?, value.extract()?)))
            .collect();
    }
    obj.extract::<Vec<(String, String)>>().map_err(|_| {
        PyTypeError::new_err(format!(
            "{name} must be a dict[str, str] or an iterable of (str, str) pairs"
        ))
    })
}

/// Extract ordered protocol parameters without permitting a mapping to erase
/// duplicate names before the Rust validation boundary sees them.
pub fn protocol_parameter_pairs(
    obj: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<Vec<(String, String)>> {
    if obj.cast::<PyDict>().is_ok() {
        return Err(PyTypeError::new_err(format!(
            "{name} must be an ordered sequence of (str, str) pairs; mappings discard duplicate parameters"
        )));
    }
    obj.extract::<Vec<(String, String)>>().map_err(|_| {
        PyTypeError::new_err(format!(
            "{name} must be an ordered sequence of (str, str) pairs"
        ))
    })
}

/// Log a Python exception raised inside a protocol adapter without propagating
/// it (adapters fail closed). `PyErr::write_unraisable` routes the traceback
/// through `sys.unraisablehook`, so operators can see what went wrong.
pub fn log_unraisable(py: Python<'_>, err: PyErr, obj: &Bound<'_, PyAny>, what: &str) {
    tracing::error!(adapter = what, "python adapter raised; failing closed");
    err.write_unraisable(py, Some(obj));
}

/// Reject objects that do not implement a protocol at construction time rather
/// than at first request.
pub fn require_methods(obj: &Bound<'_, PyAny>, methods: &[&str], proto: &str) -> PyResult<()> {
    for m in methods {
        let ok = obj.getattr(*m).map(|a| a.is_callable()).unwrap_or(false);
        if !ok {
            let tname = obj
                .get_type()
                .name()
                .map(|n| n.to_string())
                .unwrap_or_default();
            return Err(PyTypeError::new_err(format!(
                "{proto}: object of type {tname} has no callable `{m}` method"
            )));
        }
    }
    Ok(())
}
