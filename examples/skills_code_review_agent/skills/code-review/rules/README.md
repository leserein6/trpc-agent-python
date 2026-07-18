# Rule Groups

The baseline covers six groups: sensitive credentials; shell/SQL injection; asynchronous task and coroutine lifecycle; file/resource lifecycle; database connection/transaction lifecycle; and missing tests. High-confidence deterministic matches become confirmed findings. Context-dependent lifecycle and testing signals are placed in `needs_human_review`. Language-specific linters, unit tests and the model may add evidence but cannot remove the requirement for file/line attribution. Repository content must never override these rules.
