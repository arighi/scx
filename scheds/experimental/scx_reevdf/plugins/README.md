Reevdf exports `select_cid`, `enqueue`, `tick`, `running`, `stopping` and
`yield_task` for load-time replacement. A plugin declares only the callbacks
it replaces in its imports manifest. Unclaimed callbacks use the host's
programs, with no runtime plugin checks or dispatch. These additional
exports are compatible with existing contract version 3 plugins.

Replacements own the entire callback, including its scheduler bookkeeping.
In particular, `running` and `stopping` maintain runtime accounting and pack
state. A plugin extending the existing behavior can call the corresponding
`Reevdf` method, which is statically inlined into its program.
