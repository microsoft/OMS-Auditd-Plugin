SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_PROCESSOR aarch64)

# specify the cross compiler
SET(CMAKE_C_COMPILER   /opt/x-tools/aarch64-msft-linux-gnu/bin/aarch64-msft-linux-gnu-gcc)
SET(CMAKE_CXX_COMPILER /opt/x-tools/aarch64-msft-linux-gnu/bin/aarch64-msft-linux-gnu-g++)

SET(OBJCOPY /opt/x-tools/aarch64-msft-linux-gnu/bin/aarch64-msft-linux-gnu-objcopy)

# where is the target environment
SET(CMAKE_FIND_ROOT_PATH /opt/x-tools/aarch64-msft-linux-gnu)

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
#SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
#SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
#set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
# end of the file
