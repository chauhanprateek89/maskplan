# Design note: a fail-closed `init`

Status: proposal, not implemented. Written 2026-11-25.

## The problem

A column the classifier labels `none` produces no `report` finding, and the policy maps `none` to `allow` (`internal/policy/policy.go`, `Decide`). So a missed personal-data column is served raw by the views `apply` builds, and `apply`'s own report says PASS. The demo has one: `transactions.counterparty_name`. Held-out recall is about 0.87, so on a real schema this is the expected case.

Measured on the synthetic bank (`testdata/fintech`, 104 columns, scanned on 2026-11-25):

- 65 columns are labeled `none`, **every one at confidence 0.5**. The classifier never clears a column with more confidence than that, so a confidence threshold alone cannot separate "cleared" from "missed".
- The 5 personal-data columns it misses are all text: `customers.county`, `payees.reference`, `staff.staff_no`, `support_tickets.subject`, `transactions.counterparty_name`.
- Of the 65, 42 are numbers, dates or booleans, and 23 are text.

## Proposal

1. `init` writes every column the classifier cannot confidently clear as **masked**, marked `review: pending`.
2. A human clears a column by setting its label to `none` with `review: done`. Only then does it become `allow`.
3. `report` prints a warning with the count of pending columns and still exits 0. With `--strict` (or a new exit code 3), pending columns fail it, for CI.
4. `apply` keeps pending columns masked, whatever the rest of the policy says.

## What "confidently clear" means

The classifier's confidence can't be the threshold, because every `none` is 0.5. The proposal is a rule on the column's type instead:

| The scan labeled it `none`, and its type is | State |
| --- | --- |
| boolean | cleared |
| number or date/time, and no name rule matched | cleared |
| text, JSON/XML, UUID, binary, or anything else | `pending` |
| anything, `review: done` | cleared |

On the bank, this leaves 23 columns pending, and all 5 misses are among them. Numbers are not perfectly safe: a phone number or national ID stored as `bigint` under an unhelpful name would be cleared. The scanner already samples numeric columns whose name suggests one, so a later refinement could keep numbers pending when sampling saw phone-shaped values.

## YAML change

Review state is per column, and `classification.yaml` is the per-column file. It already has `reviewed: true|false`, which `scan` keeps across rescans. So the proposal is to change that file, not the policy:

```yaml
# classification.yaml, version 2
- {schema: fintech, table: transactions, column: counterparty_name, type: text,
   label: none, confidence: 0.5, review: pending}     # was: reviewed: false
- {schema: fintech, table: transactions, column: amount, type: numeric,
   label: none, confidence: 0.5, review: auto}        # cleared by the type rule
```

`review` is `pending`, `auto` or `done`. In the policy, a column that is `pending` gets the transform in a new `defaults.pending` key. `init` writes `defaults.pending: "null"` with a comment. `null` keeps the column, so agents' queries still parse; `exclude` would break them; `token` keeps joins working but namespaces the tokens under `maskplan.unlabeled`.

The alternative you sketched puts `review: pending` on per-column `overrides` in `maskplan.yaml`. That works, but it writes one line per unreviewed column into the policy (thousands on a large schema) and puts review state in two files.

## Migration

- `classification.yaml` version 1 to 2: `reviewed: true` becomes `review: done`. `reviewed: false` becomes `pending` or `auto` by the type rule. `scan` rewrites the file in place, and `Load` accepts both versions for one release.
- An existing `maskplan.yaml` has no `defaults.pending`. Defaulting it to `null` changes what `apply` serves: unreviewed text columns that were `allow` become NULL. That is the point, but it should be announced, for example as a plan warning listing each column that changes.
- `report` without `--strict` keeps today's exit codes, so existing CI does not break.

## Trade-off

Until someone reviews them, harmless columns are masked. On the bank that's 18 columns: `accounts.currency`, `accounts.status`, `cards.network`, `products.name`, `transactions.channel` and the like. Agents lose them until a human marks them `done`. Three of the 18 (`customers.nationality`, `customers.occupation`, `login_events.user_agent`) are personal data with no maskplan label yet, so masking them is arguably right.

The cost is one review pass per schema. Today, skipping that review is silently unsafe; with this change, it is safe and visible.

## Open questions for you

1. Should review state live in `classification.yaml` (recommended above) or in the policy's `overrides`, as in your sketch?
2. For `--strict`: should pending columns give exit 1, like other failures, or a new exit code 3? Either way it is a change to the CLI's exit codes.
3. What should `defaults.pending` default to: `null`, `token` or `exclude`?
4. Is the type rule acceptable, with numbers and dates cleared? Or do you want everything `none` pending until reviewed? On the bank that means 65 pending columns instead of 23.
5. Should `report` also count pending columns that the role cannot read, or only readable ones?
6. Should this ship before v0.1, or right after it with the classification format bump?
