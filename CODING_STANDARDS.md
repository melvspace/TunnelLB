# Coding Standards

## Tests

- Tautological tests considered harmful

## Blank Lines Within Functions

- Separate logical groups with one blank line.
- Add a blank line before an `if` statement when another statement precedes it.
- Add a blank line after a block before unrelated code.
- Add a blank line before a final `return` when preceded by other statements.
- Keep `else`, `catch`, `finally`, and chained calls attached to their related code.

## Codebase

- Enforce high cohesion, low coupling, and separation of concerns: split code into focused modules, organize folders by domain, and avoid monolithic files.
- Document contracts and invariants, not milestones, non-goals, or incidental implementation details.
