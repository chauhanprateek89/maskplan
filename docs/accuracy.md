# Classifier accuracy

How well `maskplan scan` labels columns, measured against hand-written ground truth. Reproduce with:

```bash
go run ./bench/fintech  -dsn "$DSN"     # load the synthetic bank into schema fintech
go run ./bench/accuracy -dsn "$DSN" -truth testdata/fintech/labels.yaml -errors
go run ./bench/accuracy -dsn "$AW_DSN" -truth testdata/adventureworks/labels.yaml -errors
go run ./bench/accuracy -dsn "$GITLAB_DSN" -review testdata/gitlab/review.yaml
```

| Dataset | Columns | Role | Precision | Recall |
| --- | --- | --- | --- | --- |
| Synthetic Irish bank, with data | 104 | held out from tuning | 0.87 | 0.87 (1.00 on the gated labels) |
| AdventureWorks, with data | 468 | tuned on | 0.86 | 0.96 |
| GitLab schema, no data | 11,143 | tuned on, recall sample held out | 0.45 (0.92 without free text) | about 0.74 (0.50 to 0.89) |
| Sakila on MySQL, with data | 89 | held out from tuning | 0.81 | 0.87 |

Raw results, including every misclassified column and its evidence, are in `bench/results/accuracy-*.json`. Measured on PostgreSQL 16, 2026-10-18.

## Method

Ground truth lists every personal-data column with its label; every other column is `none`. It was written before the classifier was run on the dataset. A scan's label for each column is compared with it, giving precision and recall per label, and for "any personal data" regardless of label. A column scored as a false negative is one `report` will never flag, because the report only checks labeled columns; a false positive costs a reviewer a look. The two are not equally bad, and the classifier leans toward false positives where it must choose.

Each dataset was scanned with 100, 1,000 and 10,000 sampled rows per table.

## Datasets and results

### Synthetic Irish bank (`testdata/fintech`)

Twelve tables and a materialized view, 104 columns, 10,000 customers: IBANs in printed and electronic form from five countries, card numbers stored as `bigint` and typed with spaces or dashes, PPSNs, Eircodes, Irish phone numbers in four formats, emails with junk values, a phone column that is NULL in the oldest 30% of rows, a partitioned transactions table, a JSONB KYC document, and hard negatives (barcodes, terminal IDs, 16-digit order references that fail Luhn, sort codes, BICs).

It is held out from tuning: it was built and first scored after the AdventureWorks changes below, and nothing was changed for it, then or after the GitLab changes. Its numbers have not moved. It is not blind: its author knew the classifier's rules.

**The accuracy gate** (CI, `internal/fintech`): recall of at least 0.95 for email, IBAN, card number and phone at each sample size. It passes:

| Label | Columns | Recall | Precision | False positives |
| --- | --- | --- | --- | --- |
| Email | 3 | 1.00 | 1.00 | |
| Bank account (IBAN) | 5 | 1.00 | 0.71 | `bic`, `sort_code` (name rule) |
| Card number | 3 | 1.00 | 1.00 | |
| Phone | 4 | 1.00 | 0.67 | `ean` barcodes, `terminal_id` (8 digits, no name rule) |
| Any personal data | 39 | 0.87 | 0.87 | also `products.description` |

Missed: `county`, `staff_no`, `counterparty_name`, and two free-text columns with uninformative names (`reference`, `subject`). Results were identical at all three sample sizes: every column here is uniform, so a detector that matches 80% of 100 rows matches 80% of 10,000.

### AdventureWorks (Postgres port)

Microsoft's AdventureWorks 2014 OLTP sample, via [lorint/AdventureWorks-for-Postgres](https://github.com/lorint/AdventureWorks-for-Postgres): 70 tables and materialized views, 468 columns, real-world naming (lowercased CamelCase without separators). Only the ground truth is in this repository (`testdata/adventureworks/labels.yaml`), not the data.

The classifier was tuned on it, so the "after" numbers are measured on training data:

| | Precision | Recall |
| --- | --- | --- |
| Any personal data, before | 0.38 | 0.77 |
| After the AdventureWorks changes | 0.74 | 0.96 |
| After the GitLab changes too | 0.86 | 0.96 |

What tuning changed, each as a general rule rather than an AdventureWorks special case:

- A bare `name` column is a person's name only in a table whose name says it holds people; it had been labeling every department, product and currency (23 false positives).
- The phone detector no longer overrides a name rule for another label: 7 to 15 digits also describes national IDs, card numbers and account numbers.
- Names without separators (`reviewername`, `nationalidnumber`), logins and usernames, password salts, gender and marital status are recognized.
- Surrogate keys (`customer_id`) are not labeled; business identifiers people are known by (`customer_no`) are.

Remaining false positives are deliberate: `description` columns are free text (payment descriptions carry names), and `accountnumber` is read as a bank account. The one miss is a geography column. Its numbers were the same at 100, 1,000 and 10,000 sampled rows only after a scanner fix: documents were cut to 256 bytes, which in AdventureWorks' contact XML is all namespace declarations, so a larger sample found the documents and then saw nothing in them.

### GitLab (schema only)

GitLab's `db/structure.sql`: 1,096 tables and 11,143 columns, loaded without data, as a fresh install has none. This measures what names and types alone can do, on the naming of a large real application. Only the review is in this repository (`testdata/gitlab/review.yaml`, with the schema's SHA-256), not the schema.

Without full ground truth, it was reviewed two ways. Every column `scan` labeled was judged by hand (precision). For recall, 400 of the columns it left as `none` were drawn at random, after the last rule change, and judged; the miss rate in that sample, scaled to all 10,637 unlabeled columns, estimates the false negatives. The criteria are in the review file; the judge was maskplan's author.

| Label | Correct / labeled | Precision |
| --- | --- | --- |
| Credentials (`system.authentication`) | 127 / 127 | 1.00 |
| Email | 26 / 30 | 0.87 |
| IP address | 14 / 15 | 0.93 |
| Phone, address | 5 / 5 | 1.00 |
| Name | 15 / 18 | 0.83 |
| Unique identifier | 7 / 17 | 0.41 |
| Free text | 36 / 294 | 0.12 |
| Any personal data | 230 / 506 | 0.45 |

Without free text, precision is 0.92. Free text is low on an empty schema by design: `description`, `note` and `message` columns are labeled because people write names into them, and most of GitLab's describe configuration; and a JSON column with no rows to sample is assumed to be free text unless its name says it holds configuration. On a database with data, JSON is judged by what is inside it. Unique identifiers lose most to integration credentials stored as `username` (a registry's, a Jira server's), which are not about a person.

Recall: 3 misses in the 399 judged sampled columns (a hash of card details, a chat username, audit details in a text column), so about 80 missed columns in all and recall about 0.74, with a 95% interval of 0.50 to 0.89. A fourth sampled column, a device fingerprint, has no label in maskplan yet and is not counted.

GitLab drove these rules, each general:

- A name rule must fit the type: a boolean, a timestamp or (for most labels) a number named like an email is not one (`email_confirmed`, `email_sent_at`). A name ending in `_id` is a key.
- `email` and `phone` may be followed only by qualifiers (`email_primary`, `phone_2`), not by any word (`email_restrictions`, `email_message_id`).
- A table "holds people" by its last word (`customer_contacts`, `users`), not by containing one (`personal_access_tokens`, `member_roles`).
- Machine addresses (`smtp_address`) and system text (`error_message`) are not personal data.
- Documents are judged by their keys and values when sampled; JSON keys and XML tags are matched against the name rules, and values against the detectors.
- Author, committer and similar role names (`author_name`), credentials and signing keys, and the `content` of message-like tables are recognized.

**Report on the same schema:** for a role that can read every table, `report` took 1.4 s and found 538 raw columns, plus 47 UNKNOWN from GitLab's own monitoring views, which call functions over the system catalogs that the report does not follow.

### Sakila (MySQL)

MySQL's sample DVD-rental database, from [jOOQ/sakila](https://github.com/jOOQ/sakila), scored with the classifier as it stood after the GitLab changes and the first run of `scan` on MySQL. Nothing was tuned on it. Only the ground truth is in this repository (`testdata/sakila/labels.yaml`).

Precision 0.81 and recall 0.87 for personal data, the same at all three sample sizes. Every name, email, phone, username and password column is found. Missed: `address2`, because the address rule allows `address_line_2` but not a bare digit, and `district`. False positives: `city.city`, a reference table of city names, and two film descriptions.

## Known gaps

- **No label yet** for salary or income, nationality, occupation, user agent, card expiry, location coordinates, photos or device fingerprints. They count as `none` in the ground truths.
- **Hashed identifiers** (a hash of a card number or an email) are still personal data; nothing detects them yet.
- **No value detector** for national IDs, postal codes, names or addresses: those rely on column names, so a `col_a` full of PPSNs is missed.
- **Sample size made no difference** on the datasets with data, once documents were read in full. A column where personal data is a minority of values would show one; none of them has such a column yet.
- **MySQL** has one small dataset so far. Next: OpenEMR's schema for false positives on real-world names.
