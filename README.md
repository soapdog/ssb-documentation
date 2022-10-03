# ssb-documentation
A repository to contain all of SSB documentation


## Current status

> **ATTENTION:** There are a lot of hardcoded values in the script inside `scripts`. I'm still
> getting all this to work. Once it is working, I'm going to remove them.

There is a lot of work going on on the build scripts and the source. Currently, this is not stable at all and it is not working. I just pushed it to the repo so that I can work in the open.


## Folder organisation

- `content/`: holds all the documentation content.
- `docs/`: holds the generated static website.
- `scripts/`: contains auxiliary scripts to work with this repository and build the static site.
- `templates/`: contains the necessary assets for the static site generation (html templates, css, images, etc).

# Working with this repository

Some of the most common tasks someone might want to do are:

### Assembling the static site

```
$ ./scripts/lua/build.lua [--verbose]
```

## Dependencies

* [Pandoc](https://pandoc.org)
* [Lua](https://lua.org)
* [Luarocks](https://luarocks.org)

Check out `scripts/install_dependencies.sh` to install Lua dependencies. You need Lua 5.3 (or Lua 5.4). This is not compatible with LuaJIT or Lua 5.1.