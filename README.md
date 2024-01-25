# mpc_laplace_noise

# How to build on Linux
```
mkdir build
cd build
cmake ..
make
```

[Release mode]
```
mkdir release
cd release
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Installation Requirements

[GMP] (https://gmplib.org/)
```
apt install libgmp-dev # on Ubuntu
```

[GTest]
```
git clone https://github.com/google/googletest.git
cd googletest
mkdir build
cd build
cmake ..
make
sudo cp -r ~/googletest/googlemock/include/gmock /usr/local/include/gmock
sudo cp -r ~/googletest/googlemock/include/gtest /usr/local/include/gtest
sudo cp ~/googletest/build/lib/*.a /usr/local/lib/
```

[OpenSSL] (confirmed by OpenSSL 1.1.1f 31 Mar 2020)
```
apt install libssl-dev # on Ubuntu 
```
<!-- 
[fmt]
```
apt install libfmt-dev # on Ubuntu 
``` -->

<!-- [mcl]
```
git clone https://github.com/herumi/mcl.git
cd mcl
mkdir build
cd build
cmake ..
make
sudo cp -r ~/mcl/include/cybozu /usr/local/include/cybozu
sudo cp -r ~/mcl/include/mcl /usr/local/include/mcl
sudo cp ~/mcl/build/lib/libmcl.a /usr/local/lib/
``` -->
