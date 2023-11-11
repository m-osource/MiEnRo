$ wget https://github.com/catchorg/Catch2/archive/refs/tags/v2.13.6.zip
$ unzip v2.13.6.zip
$ cd Catch2-2.13.6
$ cmake -Bbuild -H. -DBUILD_TESTING=OFF
$ sudo cmake --build build/ --target install
