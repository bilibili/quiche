# Compilation

**1. Prerequisite**

> apt-get install git cmake build-essential protobuf-compiler libprotobuf-dev golang-go libunwind-dev libicu-dev

**2. Build**  
> git clone https://github.com/bilibili/quiche.git && cd quiche  
> git submodule update --init  
> mkdir -p build  
> cd build && cmake ..  
> make -j  
- **NOTE**
  *in Debug build mode, you may have to type like:*
> cmake -DCMAKE_BUILD_TYPE=Debug ..
  *if you need to enable gdb debug and asan，you may have to type like:*
> cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address -fsanitize=leak -g" -DCMAKE_C_FLAGS="-fsanitize=address -fsanitize=leak -g" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address -fsanitize=leak" -DCMAKE_MODULE_LINKER_FLAGS="-fsanitize=address -fsanitize=leak"

# Upgrade
**1. Download google quiche and googleurl(if needed)**  
> git clone https://quiche.googlesource.com/quiche google_quiche
> git clone https://quiche.googlesource.com/googleurl

**2. Select a proper tag from chromium and find out quiche version and boringssl version it depended on, then checkout it.**
> git checkout [commit-id]

**3. Rewrite**  
> cp -fr google_quiche/* quiche/
> cp -fr googleurl/* quiche/googleurl/
> cd quiche && bash utils/google_quiche_rewrite.sh

**4. Check if any file or dir should be checkouted**
> git checkout README.md

**5. Update VERSION, log chromium tag and quiche/boringssl version**

**6. Compile and fix errors**  
> Repeate Compilation steps and fix errors.
