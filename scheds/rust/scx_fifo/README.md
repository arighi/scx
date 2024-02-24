# scx_fifo

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_fifo is a simple scheduler that implements a simple FIFO policy in
user-space.

## Typical Use Case

This scheduler is provided as a simple template that can be used as a baseline
to test more complex scheduling policies.

## Production Ready?

Definitely not. Using this scheduler in a production environment is not
recommended, unless there are specific requirements that necessitate a basic
FIFO scheduling approach. Even then, it's still recommended to use the kernel's
SCHED_FIFO real-time class.
