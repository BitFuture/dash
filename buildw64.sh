DASH_ROOT=$(pwd)
BDB_PREFIX="${DASH_ROOT}/db4"
mkdir -p $BDB_PREFIX
cd /home/adminuser/suncoin/BerkeleyDB4.8/build_unix/
../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX
make install
cd $DASH_ROOT
cd depends
make HOST=x86_64-w64-mingw32 -j4
cd ..
./autogen.sh
./configure --prefix=`pwd`/depends/x86_64-w64-mingw32   LDFLAGS="-L${BDB_PREFIX}/lib/" CPPFLAGS="-I${BDB_PREFIX}/include/"  
make
