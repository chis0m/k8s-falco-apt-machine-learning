# Falco Alert Column Reference

The dataset has **36 columns** after flattening the nested JSON alert records. Most are sparse and rule-specific. Below are the columns that actually matter for this project, used in the EDA, feature engineering, or modelling.

## Core columns

| Column | Meaning |
|---|---|
| `label` | `attack` or `normal`. This is the target variable. |
| `priority` | Falco's own severity rating: `Debug`, `Notice`, `Warning`, `Error`, `Critical`. |
| `rule` | Name of the Falco rule that triggered the alert (e.g. "Launch Privileged Container", "Write below root"). |
| `tags` | A list of labels Falco attaches to the alert, includes category tags (`network`, `filesystem`, `process`) and, when relevant, MITRE ATT&CK tactic tags (`mitre_persistence`, `mitre_discovery`, etc.). |
| `time` | Timestamp the alert was generated. |
| `source` | Falco's alert source which is `syscall` for every row in this dataset. |
| `output` | The full, human-readable log line describing the alert (raw text). |

## `output_fields.*`:  alert context details

| Column | Meaning |
|---|---|
| `output_fields.proc.cmdline` | The actual command that was run when the alert triggered (e.g. `bash`, `curl http://...`). |
| `output_fields.proc.name` | Name of the process that triggered the alert. |
| `output_fields.user.name` | Linux user the process ran as (`root`, `bin`, `www-data` in this dataset). |
| `output_fields.container.id` | ID of the container the alert came from. |
| `output_fields.container.image.repository` | Container image name (e.g. `busybox`, `falcosecurity/event-generator`, `nginx`). |
| `output_fields.k8s.pod.name` | Kubernetes Pod name the alert originated from. |
| `output_fields.k8s.ns.name` | Kubernetes namespace (constant `default` across this whole dataset). |
| `output_fields.fd.name` | File path involved, for file-related alerts only. |

Many other `output_fields.*` columns exist (e.g. `evt.arg.uid`, `proc.tty`, `container.mounts`) but are missing for 85–100% of rows, they only apply to specific Falco rule types and aren't used directly as model features.