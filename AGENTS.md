# Swift Editing Rules

- Always read the complete target file before modifying it.
- Preserve all existing code unrelated to the requested fix.
- Prefer minimal edits using exact replacements or patches.
- Never replace an entire file with a partial code snippet.
- Never delete unrelated imports, properties, methods or extensions.
- After editing, inspect the diff.
- If unrelated code was removed, restore it before finishing.
- Do not rewrite entire files unless explicitly requested.
