/*!
This crate provides three types that represent hash values specifically for the [`Url`] types. 

For some URL-centric structures such as RDF graphs and XML documents, there becomes a core requirement to manage
hash-like operations to compare URL values or to detect the presence of a URL in a cache. While Rust's built-in hash
implementation, and by extension collections such as `HashMap` and `HashSet`, may be used they provide a closed
implementation that cannot be used in a language-portable, or persistent manner without effort. This

The purpose of the type [`UrlHash`] is to provide a stable value that represents a stable cryptographic hash of a single
URL value that can be replicated across different platforms, and programming environments. 

# Example

```rust
use url::Url;
use url_hash::UrlHash;

let url = Url::parse("https://doc.rust-lang.org/").unwrap();
let hash =  UrlHash::from(url);
println!("{}", hash);
```

# Specification

This section attempts to describe the implementation in a language and platform neutral manner such that it may be
replicated elsewhere.

## Calculation

The basis of the hash is the SHA-256 digest algorithm which is calculated over a partially-canonical URL.

1. The `scheme` component of the URL is converted to lower-case.
2. The `host` component of the URL is converted to lower-case.
3. The `host` component has Unicode normalization via punycode replacement.
4. The `port` component is removed if it is the default for the given scheme (80 for `http`, 443 for `https`, etc.).
5. The `path` component of the URL has any relative components (specified with `"."` and `".."`) removed.
6. An empty `path` component is replaced with `"/"`.
7. The `path`, `query`, and `fragment` components are URL-encoded.

The following table demonstrates some of the results of the rules listed above.

| # | Input                                      | Output                                    |
|---|--------------------------------------------|-------------------------------------------|
| 1 | `hTTpS://example.com/`                     | `https://example.com/`                    |
| 2 | `https://Example.COM/`                     | `https://example.com/`                    |
| 3 | `https://exâmple.com/`                     | `https://xn--exmple-xta.com/`             |
| 3 | `https://example§.com/`                    | `https://xn--example-eja.com/`            |
| 4 | `http://example.com:80/`                   | `http://example.com/`                     |
| 4 | `https://example.com:443/`                 | `https://example.com/`                    |
| 5 | `https://example.com/foo/../bar/./baz.jpg` | `https://example.com/bar/baz.jpg`         |
| 6 | `https://example.com`                      | `https://example.com/`                    |
| 7 | `https://example.com/hello world`          | `https://example.com/hello%20world`       |
| 7 | `https://example.com/?q=hello world`       | `https://example.com/?q=hello%20world`    |
| 7 | `https://example.com/?q=hello#to world`    | `https://example.com/?q=hello#to%20world` |

## Representation

The resulting SHA-256 is a 256 bit, or 32 byte value. This is stored as four 64-bit (8 byte) unsigned integer values which
are converted from the digest bytes in little endian order. The following code demonstrates the creation of these values
from the bytes representing the digest.

The following code demonstrates the creation of these four values from the digest bytes.

```rust,no_run
# fn digest_bytes() -> [u8;32] { todo!() }
let bytes: [u8;32] = digest_bytes();

let value_1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
let value_2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
let value_3 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
let value_4 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
```

## Short Forms

In some cases it is not necessary to store or pass around the entire `UrlHash` 32-byte value when a trade-off for hash
collision over space may be safely made. To allow for these trade-offs each `UrlHash` instance may be converted into a
16-byte `UrlShortHash` which contains only the first two 64-bit unsigned values of the full hash, or an 8-byte
`UrlVeryShortHash` which contains only the first 64-bit unsigned value of the full hash.

The following code demonstrates the creation of short (truncated) hashes as well as the prefix tests `starts_with` and
`starts_with_just`.

```rust
# use url::Url;
# use url_hash::UrlHash;
let url = Url::parse("https://doc.rust-lang.org/").unwrap();
let hash =  UrlHash::from(url);

let short = hash.short();
assert!(hash.starts_with(&short));

let very_short = hash.very_short();
assert!(short.starts_with(&very_short));
assert!(hash.starts_with_just(&very_short));

assert_eq!(very_short, hash.very_short());
```

*/

#![warn(
    unknown_lints,
    // ---------- Stylistic
    absolute_paths_not_starting_with_crate,
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    macro_use_extern_crate,
    nonstandard_style, /* group */
    noop_method_call,
    rust_2018_idioms,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    // ---------- Future
    future_incompatible, /* group */
    rust_2021_compatibility, /* group */
    // ---------- Public
    missing_debug_implementations,
    // missing_docs,
    unreachable_pub,
    // ---------- Unsafe
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    // ---------- Unused
    unused, /* group */
)]
#![deny(
    // ---------- Public
    exported_private_dependencies,
    // ---------- Deprecated
    anonymous_parameters,
    bare_trait_objects,
    ellipsis_inclusive_range_patterns,
    // ---------- Unsafe
    deref_nullptr,
    drop_bounds,
    dyn_drop,
)]

use std::fmt::Display;
use url::Url;
use ring::digest;

// ------------------------------------------------------------------------------------------------
// Public Types
// ------------------------------------------------------------------------------------------------

///
/// This type represents a secure, stable, hash value for a [`Url`] using an SHA-256 digest
/// algorithm. While this hash may be tested for equality (and strict inequality) no other
/// relations, such as ordering, are supported. 
///
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UrlHash([u64;4]);

///
/// This type contains the first half of a [`UrlHash`] instance where a less secure test using a
/// truncated hash value is acceptable.
///
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UrlShortHash([u64;2]);

///
/// This type contains the first quarter of a [`UrlHash`] instance where a less secure test using
/// a truncated hash value is acceptable.
///
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UrlVeryShortHash(u64);

// ------------------------------------------------------------------------------------------------
// Public Functions
// ------------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------------
// Implementations
// ------------------------------------------------------------------------------------------------

impl Display for UrlHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-{}-{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl From<Url> for UrlHash {
    fn from(value: Url) -> Self {
        let url = value.to_string();
        let hash = digest::digest(&digest::SHA384, url.as_bytes());
        let bytes = hash.as_ref();
        assert!(bytes.len() >= digest::SHA256_OUTPUT_LEN);
        Self([
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ])
    }
}

impl UrlHash {
    ///
    /// Return a [`UrlShortHash`] instance containing the first two values of this hash.
    ///
    #[inline]
    pub fn short(&self) -> UrlShortHash {
        UrlShortHash(self.0[0..2].try_into().unwrap())
    }

    ///
    /// Return a [`UrlVeryShortHash`] instance containing only the first value of this hash.
    ///
    #[inline]
    pub fn very_short(&self) -> UrlVeryShortHash {
        UrlVeryShortHash(self.0[0])
    }

    ///
    /// Does this hash start with the two values in the provided short hash?
    ///
    #[inline]
    pub fn starts_with(&self, short_hash: &UrlShortHash) -> bool {
        self.0[0] == short_hash.0[0] && self.0[1] == short_hash.0[1]
    }

    ///
    /// Does this hash start with the value in the provided very-short hash?
    ///
    #[inline]
    pub fn starts_with_just(&self, very_short_hash: &UrlVeryShortHash) -> bool {
        self.0[0] == very_short_hash.0
    }
}

// ------------------------------------------------------------------------------------------------

impl Display for UrlShortHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.0[0], self.0[1])
    }
}

impl UrlShortHash {
    ///
    /// Return a [`UrlVeryShortHash`] instance containing only the first value of this short hash.
    ///
    #[inline]
    pub fn very_short(&self) -> UrlVeryShortHash {
        UrlVeryShortHash(self.0[0])
    }

    ///
    /// Does this hash start with the value in the provided very-short hash?
    ///
    #[inline]
    pub fn starts_with(&self, very_short_hash: &UrlVeryShortHash) -> bool {
        self.0[0] == very_short_hash.0
    }
}

// ------------------------------------------------------------------------------------------------

impl Display for UrlVeryShortHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ------------------------------------------------------------------------------------------------
// Modules
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_url_repeatedly() {
        let url = Url::parse("https://doc.rust-lang.org/std/primitive.u8.html#method.to_ascii_lowercase").unwrap();
        let first =  UrlHash::from(url);

        for _ in 1..1000 {
            let url = Url::parse("https://doc.rust-lang.org/std/primitive.u8.html#method.to_ascii_lowercase").unwrap();
            let again =  UrlHash::from(url);
            assert_eq!(again, first);
        }
    }

    #[test]
    fn test_another_url() {
        let url = Url::parse("https://www.google.com/search?q=rust+hash+url+value&rlz=1C5GCEM_enUS1025US1025&oq=rust+hash+url+value&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBCDYyOTlqMGo0qAIAsAIA&sourceid=chrome&ie=UTF-8").unwrap();
        let _ = UrlHash::from(url);
    }

    #[test]
    fn test_hash_prefixes() {
        let url = Url::parse("https://doc.rust-lang.org/std/primitive.u8.html#method.to_ascii_lowercase").unwrap();
        let hash =  UrlHash::from(url);
        println!("{}", hash);

        let short = hash.short();
        println!("{}", short);
        assert!(hash.starts_with(&short));

        let very_short = hash.very_short();
        println!("{}", very_short);
        assert!(short.starts_with(&very_short));
        assert!(hash.starts_with_just(&very_short));
    }

    #[test]
    fn test_url_prereq_scheme_case() {
        assert_eq!(
            Url::parse("hTTpS://example.com/").unwrap().as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_url_prereq_host_case() {
        assert_eq!(
            Url::parse("https://Example.COM/").unwrap().as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_url_prereq_host_punycode() {
        assert_eq!(
            Url::parse("https://exâmple.com/").unwrap().as_str(),
            "https://xn--exmple-xta.com/"
        );

        assert_eq!(
            Url::parse("https://example§.com/").unwrap().as_str(),
            "https://xn--example-eja.com/"
        );
    }

    #[test]
    fn test_url_prereq_port_default() {
        assert_eq!(
            Url::parse("http://example.com:80/").unwrap().as_str(),
            "http://example.com/"
        );

        assert_eq!(
            Url::parse("https://example.com:443/").unwrap().as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_url_prereq_path_normalize() {
        assert_eq!(
            Url::parse("https://example.com/foo/../bar/./baz.jpg").unwrap().as_str(),
            "https://example.com/bar/baz.jpg"
        );
    }

    #[test]
    fn test_url_prereq_empty_path_slash() {
        assert_eq!(
            Url::parse("https://example.com").unwrap().as_str(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_url_prereq_encode_path() {
        assert_eq!(
            Url::parse("https://example.com/hello world").unwrap().as_str(),
            "https://example.com/hello%20world"
        );
    }

    #[test]
    fn test_url_prereq_encode_query() {
        assert_eq!(
            Url::parse("https://example.com/?q=hello world").unwrap().as_str(),
            "https://example.com/?q=hello%20world"
        );
    }

    #[test]
    fn test_url_prereq_encode_fragment() {
        assert_eq!(
            Url::parse("https://example.com/?q=hello#to world").unwrap().as_str(),
            "https://example.com/?q=hello#to%20world"
        );
    }
}
