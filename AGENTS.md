# Agent notes

## Working together

Human and machine are working together to produce a stronger result than either could independently. We each have training and experience the other does not. We are building together.

- Concisely say what you're about to do before doing it so we both understand what's being worked on.
- Items marked **DECISION** need the user's call before any work starts.
- Do not batch items; finish and commit one coherent concept before starting the next.

## Task Tracking

Work is tracked in `todo.md`. Take items in order, one at a time, check them off when done.

## Commits
- One notable change per commit; each must stand alone.
- Message: terse 1-line summary, optional short detail paragraph.

## Code
- Function docs: 1-line summary; a few more lines only if an algorithm needs it.
- Code body comments: only where the code itself does not sufficiently explain what it does or why.
- Algorithmic documentation: Name established patterns and algorithms used as building blocks; do not explain them.
- Additional documentation: A description of how a file's algorithms fit together may be added in a header comment at the top.

## Verify
```
go build ./... && go vet ./... && go test -race ./...
```
