# Writing Standard

Every agent and human follows this when writing the README, docs, specs, DONE/LESSONS entries, PR descriptions, commit messages and code comments. The goal is text a busy engineer can act on after one read.

---

## 1. Rules

1. **Say what it does, then how to use it.** Lead with the fact, not the setup ("This CLI converts X to Y", not "In today's world, converting X...").
2. **Every claim is checkable.** Don't write "fast" or "secure" without a number or a mechanism ("p95 120 ms on 1k rows", "passwords hashed with argon2id").
3. **Every command is copy-pasteable and was run.** Show the real command and the real output. Never invent flags, file names, versions or output.
4. **Describe only what exists.** No planned features, no "coming soon", no options the code doesn't have. Roadmap items belong in `TODO.md`.
5. **One place per fact.** Link instead of repeating: setup steps live in the README, rules in `AGENTS.md`, requirements in `docs/requirements/`.
6. **Short beats complete.** If a section doesn't help someone install, run, change or debug the project, cut it.
7. **Plain words.** Write "use", not "leverage"; "lets you", not "empowers". Explain a term the first time you use it.
8. **Update it in the same change.** When behaviour, commands or config change, the doc changes in the same commit.

## 2. Banned (slop)

| Don't write | Write instead |
|-------------|---------------|
| seamless, robust, powerful, cutting-edge, state-of-the-art, blazing fast, effortless, comprehensive, world-class, next-generation | the specific fact, or nothing |
| leverage, utilize, empower, harness, unlock, elevate, streamline | use, lets you, makes X faster (by how much) |
| "In today's fast-paced world…", "Whether you're a beginner or an expert…", "Let's dive in!", "Look no further" | start with what it does |
| "It's important to note that…", "Simply…", "Just…", "Easily…" | the note itself, with no lead-in |
| Emoji in headings or bullets (🚀 ✨ 🔥 ✅) | nothing |
| Badges for CI, coverage or downloads that don't exist | only badges backed by a real, working source |
| A "Features" list restating the obvious ("✅ Written in Python", "✅ Open source") | the 3 to 5 things a user would choose this for |
| A table of contents in a README under ~8 sections | nothing |
| Closing summaries ("In conclusion…", "With X you can now…") | stop when the content ends |
| Comments that restate the code (`i += 1  # increment i`) | a comment only for a *why* the code can't show |
| Commit or PR text like "Updated files", "Various improvements", "Fixed stuff" | `FR-012: reject expired tokens in /login` |

## 3. README template

Replace the skeleton's README with this when you start a project. Delete sections that don't apply, rather than leaving them empty.

````markdown
# <Project name>

<One sentence: what it does and for whom.>

<Optional: one short paragraph on the problem it solves or how it works. No adjectives.>

## Requirements

- <runtime + version, e.g. Python 3.11+>
- <external services, e.g. PostgreSQL 15>

## Install

```bash
<exact commands>
```

## Usage

```bash
<the most common command>
```

<Real output, trimmed. Then 1 or 2 more examples only if they're common.>

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `APP_PORT` | `8080` | HTTP port |

## Development

```bash
<run tests>
<run lint>
```

How we work (requirements → spec → test → verify): see `AGENTS.md` and `docs/WORKFLOW.md`.

## Project layout

<Only if it is not obvious. 5 to 10 lines max.>

## License

<license name>, see `LICENSE`.
````

## 4. Check before saving

- [ ] The first sentence says what it is. A stranger could explain the project after reading it.
- [ ] Every command was run in this change, and the output shown is real.
- [ ] No word from the Banned table. Search the text for a few of them.
- [ ] No section describes something that doesn't exist yet.
- [ ] Nothing is repeated that already lives in another doc. It links instead.
- [ ] It is shorter than the first draft.
