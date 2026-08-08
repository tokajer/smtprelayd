# Session Bootstrap

How to start a new chat without re-explaining the project.

## The routine

1. Start a **new chat per phase**. Context from a finished phase is dead weight.
2. Attach or paste `CLAUDE.md`, `MEMORY.md` and `PROGRESS.md`. Nothing else.
3. Use the opening prompt below.
4. At the end of the session, ask for an updated `PROGRESS.md` and commit it.

## Opening prompt

> Anbei CLAUDE.md, MEMORY.md und PROGRESS.md eines Go-Projekts.
> Lies sie, dann arbeite ausschließlich an der nächsten offenen Phase.
> Gib nur geänderte Dateien aus, keine unveränderten. Am Ende: aktualisiertes
> PROGRESS.md und eine Conventional-Commit-Message.
> Kurze Rückfragen sind erwünscht, lange Zusammenfassungen nicht.

## Closing prompt

> Fasse den Stand als aktualisiertes PROGRESS.md zusammen und gib mir die
> Commit-Message. Sonst nichts.

## What wastes tokens

| Habit | Better |
|---|---|
| One long chat across all phases | One chat per phase |
| Pasting whole files to ask about one function | Paste the function and its signature |
| Letting the assistant reprint unchanged files | Ask explicitly for diffs only |
| Re-deriving decisions already made | Point at `MEMORY.md` |
| Asking for a summary of the conversation | Ask for an updated `PROGRESS.md` instead |
| Uploading the entire repository | Upload the three context files |

## When to start a new chat

- A phase is finished.
- The topic changes substantially, for example from queue internals to the
  dashboard.
- The assistant starts repeating itself or forgetting earlier decisions — the
  context window is saturated and every further message costs more for less.
