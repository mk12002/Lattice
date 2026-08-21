# Getting a DOI via Zenodo

A **DOI (Digital Object Identifier)** is a permanent, citable identifier. Archiving a
GitHub release on **Zenodo** mints one automatically, so instead of handing someone a
GitHub URL you can write *"Lattice v0.4.0, DOI: 10.5281/zenodo.XXXXXXX."* This is the
single cheapest credibility upgrade for the project.

Lattice is already prepared for this: [`CITATION.cff`](https://github.com/mk12002/Lattice/blob/main/CITATION.cff) supplies the
citation metadata Zenodo reads.

## One-time setup (maintainer action — needs your Zenodo/GitHub accounts)

1. Sign in at <https://zenodo.org> with GitHub (or link your GitHub account under
   Zenodo → *Settings → GitHub*).
2. On the Zenodo **GitHub** page, find `mk12002/Lattice` and flip its toggle **On**. This
   tells Zenodo to archive future releases of this repo.
3. (Optional) Pre-reserve a concept DOI so you can put the badge in the README before the
   first release: Zenodo → *New upload → Reserve DOI*. Otherwise the DOI appears after the
   first release.

## Cut the release that gets archived

```bash
# ensure version is bumped and CHANGELOG updated (see docs/RELEASING.md), then:
git tag v0.4.0
git push origin v0.4.0
```

Publishing a GitHub **Release** from that tag (the `release.yml` workflow does this
automatically) triggers Zenodo, which archives the source tarball and mints:

- a **version DOI** (points at exactly v0.4.0), and
- a **concept DOI** (always points at the latest version).

## Add the badge

After the first release, Zenodo shows a badge on the archive page. Add it near the top of
`README.md` (a placeholder is already there — replace the id):

```markdown
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXX)
```

and set the same DOI in `CITATION.cff`:

```yaml
doi: 10.5281/zenodo.XXXXXXX
```

## Then you can cite it properly

> Lattice contributors. *Lattice: a crypto-agility and post-quantum-readiness scanner*,
> version 0.4.0, 2026. Zenodo. https://doi.org/10.5281/zenodo.XXXXXXX

GitHub also renders a **"Cite this repository"** button from `CITATION.cff`, and once the
DOI is set there, that button offers a DOI-anchored citation.
