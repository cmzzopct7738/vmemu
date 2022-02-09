# vmemu

VMProtect 3 Virtual Machine Handler Emulation

# Build Requirements

```
clang-10 
cmake (3.x or up)
```

*linux build instructions*

```
# must be clang 10 or up
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++

# clone and build
git clone https://githacks.org/vmp3/vmemu
cd vmemu
cmake -B build
cd build 
make
```