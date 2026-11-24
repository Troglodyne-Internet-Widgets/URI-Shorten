# URI-Shorten

This distribution is URI::Shortener. It shortens URIs and stores them in sqlite, Postgres or MySQL.
Dist::Zilla builds it from `dist.ini`.

## Layout

- `lib/URI/Shortener.pm`: the whole module and its POD.
- `t/`: tests that run with sqlite in memory.
- `xt/`: tests that need a live Postgres or MySQL server.
- `prereqs.yml`: prerequisites that AutoPrereqs cannot find in the code.

## Rules

- Before each commit, run `prove -l t`. The hooks in `git-hooks/` run the checks too.
- Run `perlcritic --profile .perlcriticrc lib t` and `perltidy` with `.perltidyrc`. The code must pass both.
- Do not turn off a policy to make the code pass. If you must, name the policy in `## no critic (...)` and write the reason in a comment beside it.
- Table and index names go into SQL text. The constructor makes sure that they are plain identifiers. Pass every value through a placeholder.
- Add each change to `Changes`.
- Write documentation and `Changes` with the simple-english skill.
