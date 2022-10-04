#!env bash

if ! luarocks config --lua-ver | grep '5\.[3456789]'
then
  echo 'please first install lua >=5.3 with luarocks'
  exit -1
fi

luarocks install --local lfs
luarocks install --local penlight
luarocks install --local lua-toml
luarocks install --local f-strings

