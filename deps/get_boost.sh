#!/bin/bash

wget https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.gz
tar -xzf boost_1_88_0.tar.gz
rm boost_1_88_0.tar.gz
cd boost_1_88_0

./bootstrap.sh
mkdir ../boost
./b2 --prefix=../boost install
cd ..
rm -rf boost_1_88_0

echo "Boost has been installed to deps/boost"
