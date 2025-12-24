# Contributing Guidelines
## 1. Branch Overview

### `main`
- Stable, production-ready branch
- **Direct commits are strictly prohibited**
- Changes are merged only via Pull Requests from `dev-branch`

### `dev-branch`
- Active integration branch
- All feature development converges here
- Must always remain buildable and testable

---

## 2. Branch Naming Conventions

### Feature Branches

Used for implementing new features.


**Rules**
- Must be created from `dev-branch`
- One feature per branch
- Use kebab-case for feature names

**Examples**
- ft/port-scanner
- ft/disassembler

### Fix / Issue Branches

Used for fixing significant issues related to an existing feature.
Where:
- `fx-` → fix branch
- `#` → GitHub Issue number
- `feature-name` → related feature

**Rules**
- Must be created from the corresponding feature branch
- Issue **must exist** before creating this branch
- If the issue is significant enough, only then create one

**Examples**
- fx-12/port-scanner
- fx-8/disassembler

where the number 12 and 8 refer to the issue number opened in the issue page about the respective feature like the port-scanner or disassembler

---

## 3. Issue Management Rules

- Create GitHub Issues **only for significant bugs or architectural changes**
- Minor fixes (typos, formatting, small refactors) do not require issues
- Every issue must include:
  - Clear problem description
  - Expected behavior
  - Affected feature/module

---

## 4. Branch Flow
```
main
 └── dev-branch
      └── ft/feature-name
            └── fx-#/feature-name
```
This flow was decided so that when we fix an issue of a particular feature, it always merges with the respective feature only and after the fix passes all the tests we can merge it with the dev-branch and make a final stable production ready merge in the main branch

So the main branch is the most stable branch and the dev-branch is the continious working branch

## 5. Commit Message Guidelines

Use the following structured commit format:
type: short description

Types:

- feat: new feature
- fix: bug fix
- refactor: code refactoring
- docs: documentation
- test: tests
- chore: tooling / maintenance

Examples:
- feat: integrate port-scanner with working cli 
- docs: update setup instructions
