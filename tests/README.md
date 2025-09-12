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
Directory name with all cargo features enabled:
asserts_base-flags-type_keys-flags-type_finish_protocol

Directory name parts, each represents
an enabled cargo feature                                 Crate/feature                  Meaning
--------------------------------------------------------------------------------------------------------
asserts                                                  hash-injector/asserts          Extra asserts (same for
                                                                                        debug and release target).
                                                                                                                    
        base-flags-type                                  hash-injector/flags-type       Higher const generic type
                                                                                        InjectionFlags.
                                                                                                                      
                        keys-flags-type                  hash-injector-keys/flags-type  Higher const generic type
                                                                                        KeyFlags.
                                                                                                                    
                                        finish           hash-injector/check-finish     Check the result hash.
                                                                                                                     
                                               protocol  hash-injector/check-protocol   Protocol check between Hash
                                                                                        and Hasher. Requires
                                                                                        hash-injector/check-finish.
```
