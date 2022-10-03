# README

This folder contains the [Lua](https://lua.org) version of the scripts used to build the documentation.

> **ATTENTION:** At the moment, the build script has a hardcoded call to `mkdir -p` which ties it to UNIX-like systems. This will be removed in favour of a cross-platform solution later.

## Requirements

* [Lua >= 5.3](https://lua.org): The runtime for the Lua programming language.
* [Luarocks](https://luarocks.org): The package manager for Lua.

## Installing the dependencies

Run:

```
$ install_dependencies.sh
```