# dnpf

A BPF based tool for establishing DNS-based covert channels, for JHU 695.722 Covert Channels.

## Build Requirements

*  Docker and docker-compose
*  Vagrant

## Building

First, you must build the XDP filter program.

```
$ cd bpf/
$ docker-compose build
$ docker-compose run --rm filter-builder
$ cd ..
```
This will create the `filter_program_x86_64` program object file in the `bpf/` directory.
Then, you can run the program itself in the Linux lab environment. `scargo` is included
as an alias to run `cargo` as root for convenience.

First, start the lab environment.

```
$ cd lab/
$ vagrant up 
```

TODO

### Demo

TODO

# Licenses

All Rust code here is distributed under the MIT license. 

The BPF filter program source (`bpf/filter.c`) and subsequent artifacts are distributed under dual MIT/GPL.
