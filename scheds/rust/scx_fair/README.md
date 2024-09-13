# scx_fair

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

A scheduler that focuses on ensuring fairness among tasks.

## Typical Use Case

The ideal use case for this scheduler is with workloads that prioritize
throughput over responsiveness, such as in server environments.

## Production Ready?

Yes.
