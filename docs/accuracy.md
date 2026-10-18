# Classifier accuracy

How well `maskplan scan` labels columns, measured against hand-written ground truth. Reproduce with:

```bash
go run ./bench/fintech  -dsn "$DSN"     # load the synthetic bank into schema fintech
go run ./bench/accuracy -dsn "$DSN" -truth testdata/fintech/labels.yaml -errors
go run ./bench/accuracy -dsn "$AW_DSN" -truth testdata/adventureworks/labels.yaml -errors
```

Raw results, including every misclassified column and its evidence, are in `bench/results/accuracy-*.json`. Measured on PostgreSQL 16, 2026-10-18.

## Method

Ground truth lists every personal-data column with its label; every other column is `none`. It was written before the classifier was run on the dataset. A scan's label for each column is compared with it, giving precision and recall per label, and for "any personal data" regardless of label. A column scored as a false negative is one `report` will never flag, because the report only checks labeled columns; a false positive costs a reviewer a look. The two are not equally bad, and the classifier leans toward false positives where it must choose.

Each dataset was scanned with 100, 1,000 and 10,000 sampled rows per table.

## Datasets and results

### Synthetic Irish bank (`testdata/fintech`)

Twelve tables and a materialized view, 104 columns, 10,000 customers: IBANs in printed and electronic form from five countries, card numbers stored as `bigint` and typed with spaces or dashes, PPSNs, Eircodes, Irish phone numbers in four formats, emails with junk values, a phone column that is NULL in the oldest 30% of rows, a partitioned transactions table, a JSONB KYC document, and hard negatives (barcodes, terminal IDs, 16-digit order references that fail Luhn, sort codes, BICs).

It is held out from tuning: it was built and first scored after the changes below, and nothing was changed for it. It is not blind: its author knew the classifier's rules.

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
| Any personal data, after | 0.74 | 0.96 |

What tuning changed, each as a general rule rather than an AdventureWorks special case:

- A bare `name` column is a person's name only in a table whose name says it holds people; it had been labeling every department, product and currency (23 false positives).
- The phone detector no longer overrides a name rule for another label: 7 to 15 digits also describes national IDs, card numbers and account numbers.
- Names without separators (`reviewername`, `nationalidnumber`), logins and usernames, password salts, gender and marital status are recognized.
- Surrogate keys (`customer_id`) are not labeled; business identifiers people are known by (`customer_no`) are.

Remaining false positives are deliberate: XML documents default to `free_text`, `description` columns are free text (payment descriptions carry names), and `accountnumber` is read as a bank account. The one miss is a geography column.

## Known gaps

- **No label yet** for salary or income, nationality, occupation, user agent, card expiry or location coordinates. They count as `none` in both ground truths.
- **No value detector** for national IDs, postal codes, names or addresses: those rely on column names, so a `col_a` full of PPSNs is missed.
- **Sample size made no difference** on either dataset. A column where personal data is a minority of values would show one; neither dataset has such a column yet.
- **Two datasets, one engine.** Next: a large open-source application schema (Odoo or OpenEMR) for false positives on real-world names, and Sakila when `scan` supports MySQL.
