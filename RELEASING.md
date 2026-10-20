# Releasing

Five steps, in this order. The order is the point: the Homebrew tap must never point at an asset that does not exist yet, and a release that skips step 5 leaves `brew install` serving the **previous** version without complaining.

## 1. Bump the version

`pyproject.toml` is the single source of the version. Change the one line in `[project]`:

```toml
version = "0.1.1"
```

Add the same version to `CHANGELOG.md`.

## 2. Commit, tag, push

```bash
git commit -am "0.1.1"
git tag -a v0.1.1 -m "nullaosta 0.1.1"
git push origin main
git push origin v0.1.1
```

## 3. Build both artifacts

Build from outside the source tree: a local `build/` directory shadows the
`build` module and makes `python -m build` fail in place.

```bash
cd /tmp && python3.12 -m build --sdist --wheel --outdir ~/nullaosta/dist ~/nullaosta
```

You want both files in `dist/`: `nullaosta-<version>-py3-none-any.whl` and
`nullaosta-<version>.tar.gz`. The wheel is what `pip` and `pipx` users install;
the sdist is what the Homebrew formula builds from.

## 4. Create the release with both assets

```bash
cd ~/nullaosta
gh release create v0.1.1 dist/nullaosta-0.1.1-py3-none-any.whl dist/nullaosta-0.1.1.tar.gz
```

## 5. Bump the Homebrew tap - do not skip this

```bash
python3 tools/release_homebrew.py --tap-dir ~/homebrew-nullaosta --push
```

The tool reads the version from `pyproject.toml`, downloads the sdist it is about
to pin, hashes the bytes it actually received, rewrites the formula, re-reads it
to confirm, then commits and pushes the tap. It refuses to write a `sha256` it
could not compute, so a release that has not published its asset yet fails here
rather than silently pinning a 404.

## Prove the tap is current

From anywhere, no local clone needed:

```bash
python3 tools/release_homebrew.py --check
```

Exit `0` means the tap serves this tree's version with a sha256 that matches the
published asset. Exit `1` means the tap is stale, or hand-edited into a state
that does not match the asset, or the asset could not be downloaded at all -
the tool refuses to pin something it could not hash. Fix it by re-running step
5. This is cheap enough to run before announcing anything, and it is the guard
against the failure this repo cares about elsewhere too - a green-looking state
that is not true.

## Verify on the machine that will use it

```bash
brew update && brew upgrade nullaosta && nullaosta --version
```

## What is not automated, on purpose

Creating the release and pushing the tap both need credentials. They stay in the
hands of whoever runs the release, because a token that can publish on your
behalf is a bigger liability than a manual step. `tools/release_homebrew.py`
only ever writes `Formula/nullaosta.rb` in the tap clone it is given.
