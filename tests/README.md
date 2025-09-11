# hash-injector tests

## Directory tree

The actual test code is in [`tests-shared/`](../tests-shared). All directories **directly** under
[]`tests/`](./) are just "variations/instantiations" of [`tests-shared/`](../tests-shared/), one per
each cargo flags combination.

Each such directory (directly under `tests/`) is a [Rust virtual
workspace](https://doc.rust-lang.org/nightly/cargo/reference/workspaces.html#virtual-workspace).
That allows all the crates under it to share the same `target/` directory, hence minimizing the
build time spent on
[monomorphization](https://rustc-dev-guide.rust-lang.org/backend/monomorph.html). All crates under
the same virtual workspace (under `tests/`) differ only in `const` generic parameters (of types
`InjectionFlags` and `KeyFlags`).

### Directory naming code

Each letter indicates whether a respective cargo feature is turned on.

```
a_h_f_s
a       asserts
  h     adt-const-params (higher types for const generic flags)
    f   injector-checks-finish
      s injector-checks-same-flow (available only if injector-checks-finish is turned on, too)
```
