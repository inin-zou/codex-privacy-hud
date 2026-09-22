# Historical Privacy HUD 0.7.1 modules

Vendored, unmodified, from this repository's own history, so #66's tests can
run the **actual** historical ledger initializer rather than a re-creation of
it. A re-creation would prove nothing: the whole claim under test is that the
code users still have installed performs incompatible DDL through the original
ledger pathname, and that claim is about those bytes.

Source commit: `ad835b8aa1c58eed9e7a7b57da6da57b6ab6fed5` (merge, 2026-09-20),
the last commit before #54's prepared schema. Extracted with:

```sh
git show ad835b8:src/privacy_hud/<path> > tests/fixtures/runtime_071/privacy_hud/<path>
```

Files, and why each is here:

| Path | Why |
|---|---|
| `privacy_hud/ledger.py` | `Ledger.__init__` and `_migrate`: `executescript(SCHEMA)`, `PRAGMA journal_mode=WAL`, and `ALTER TABLE events ADD COLUMN source_kind TEXT` |
| `privacy_hud/budget.py` | imported by `ledger` (`contribution`, `percent`) |
| `privacy_hud/matrix/loader.py` | imported by `ledger` and `budget` (`Matrix`, `load_matrix`) |
| `privacy_hud/matrix/tables.toml` | the data `load_matrix` reads |
| `privacy_hud/__init__.py`, `privacy_hud/matrix/__init__.py` | empty, as they were |

`SHA256SUMS` records each file's digest; `tests/test_runtime_storage.py`
verifies it before importing anything here, so a fixture edited by accident
fails loudly instead of quietly testing something other than 0.7.1.

Nothing here is on `sys.path` for the package under test: the tests run it in a
subprocess with this directory as the only first-party path, against private
copies in a temporary directory. It is never imported into the test process,
and it never touches an installation.

No network and no `git` call is needed to use it — CI has these bytes.
