#DASH_ROOT=$(pwd)
#BDB_PREFIX="${DASH_ROOT}/db4"
#mkdir -p $BDB_PREFIX
#cd ../BerkeleyDB4.8/build_unix/
#../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX
#make install
#cd $DASH_ROOT
#./autogen.sh
#./configure LDFLAGS="-L${BDB_PREFIX}/lib/" CPPFLAGS="-I${BDB_PREFIX}/include/" 
./autogen.sh
./configure --with-incompatible-bdb  --enable-debug  --disable-tests --disable-gui-tests 
make
 

