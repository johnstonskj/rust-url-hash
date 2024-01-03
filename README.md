# Crate url-hash

This crate provides three types that represent hash values specifically for the `Url` types. 

For some URL-centric structures such as RDF graphs and XML documents, there becomes a core requirement to manage
hash-like operations to compare URL values or to detect the presence of a URL in a cache. While Rust's built-in hash
implementation, and by extension collections such as `HashMap` and `HashSet`, may be used they provide a closed
implementation that cannot be used in a language-portable, or persistent manner without effort. This

The purpose of the type `UrlHash` is to provide a stable value that represents a stable cryptographic hash of a single
URL value that can be replicated across different platforms, and programming environments. 

## Example

```rust
use url::Url;
use url_hash::UrlHash;

let url = Url::parse("https://doc.rust-lang.org/").unwrap();
let hash =  UrlHash::from(url);
println!("{}", hash);
```

## Specification

This section attempts to describe the implementation in a language and platform neutral manner such that it may be
replicated elsewhere.

### Calculation

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

### Representation

The resulting SHA-256 is a 256 bit, or 32 byte value. This is stored as four 64-bit (8 byte) unsigned integer values which
are converted from the digest bytes in little endian order. The following code demonstrates the creation of these values
from the bytes representing the digest.

The following code demonstrates the creation of these four values from the digest bytes.

``` rust
let bytes: [u8;32] = digest_bytes();

let value_1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
let value_2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
let value_3 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
let value_4 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
```

### Short Forms

In some cases it is not necessary to store or pass around the entire `UrlHash` 32-byte value when a trade-off for hash
collision over space may be safely made. To allow for these trade-offs each `UrlHash` instance may be converted into a
16-byte `UrlShortHash` which contains only the first two 64-bit unsigned values of the full hash, or an 8-byte
`UrlVeryShortHash` which contains only the first 64-bit unsigned value of the full hash.

The following code demonstrates the creation of short (truncated) hashes as well as the prefix tests `starts_with` and
`starts_with_just`.

```rust
let url = Url::parse("https://doc.rust-lang.org/").unwrap();
let hash =  UrlHash::from(url);

let short = hash.short();
assert!(hash.starts_with(&short));

let very_short = hash.very_short();
assert!(short.starts_with(&very_short));
assert!(hash.starts_with_just(&very_short));

assert_eq!(very_short, hash.very_short());
```

# Change History

**Version 0.1.0**

* Initial release.
