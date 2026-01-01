# CVEDB Strategic Roadmap (2026)

> Living implementation plan based on the 2026 architectural audit. Focus: Modularization, maintainability, and professionalization of the codebase.

## 1. Guiding Objectives

- **Architecture First**: Clean separation of concerns (Source vs. Data vs. Artifacts).
- **Package-Based**: Move away from script soup to a proper Python package (`src/cvedb`).
- **Testable**: Ensure all logic is verifiable via standard test suites.
- **Maintainable**: Clear entry points, standardized build commands, and CI/CD integration.

---

## 2. Phase 10 – Project Reorganization (Q1 2026) ✅ Complete

**Goal:** Refactor the codebase to separate source code, data, and build artifacts.

### 2.1. Directory Structure Restructure ✅
- [x] **Create `src/cvedb` package**
  - Moved analysis logic to `src/cvedb/analysis`
  - Moved CNA pipeline to `src/cvedb/cna`
  - Moved ingest logic to `src/cvedb/ingest`
- [x] **Clean Data Directory**
  - `data/` now only contains config and raw cache.
  - Removed all executable Python scripts from `data/`.
- [x] **Unified Frontend**
  - Merged `cna/templates` into `templates/`
  - Centralized static assets in `static/`
- [x] **Standardize Scripts**
  - `scripts/build.py` updated to use the package structure.
  - `Makefile` updated to support `install`, `build`, `serve` commands.

### 2.2. Package Distribution ✅
- [x] **`pyproject.toml`**
  - usage of standard `setuptools` build backend.
  - `pip install -e .` installation support.

---

## 3. Phase 11 – Test Suite Modernization (Q1 2026) ✅ Complete

**Goal:** Ensure the test suite works with the new package structure and covers critical paths.

### 3.1. Test Refactoring ✅
- [x] **Update Import Paths**
  - Tests now import from `cvedb` package instead of using `sys.path` hacks.
- [x] **Update Test Data Paths**
  - `test_build.py` verifies `dist/` instead of `web/`.
  - `test_schemas.py` validates `dist/data/` JSON outputs.

### 3.2. CI/CD Pipeline Update ✅
- [x] **`deploy.yml` Update**
  - Workflow now installs the package before testing.
  - Deploys from the new `dist/` directory.

---

## 4. Future Phases (Q2 2026+)

### 4.1. Performance & caching
- [ ] Implement incremental builds (only rebuild year files for changed data).
- [ ] Parallelize downloads in `ingest` module.

### 4.2. Analysis Enhancements
- [ ] Migrate legacy `rebuild_*.py` scripts to use the `cvedb` package API.
- [ ] Add type hinting (mypy) to the core package.