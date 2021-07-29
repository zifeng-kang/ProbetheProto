export OUT_DIR=$1
export PKG_CONFIG_PATH="/media/data1/zfk/Documents/sanchecker/src/build/linux/debian_wheezy_amd64-sysroot/usr/share/pkgconfig"
export CAPNP_INSTALL="/media/data1/zfk/Documents/capnproto-install"
export PATH="$PATH:$CAPNP_INSTALL/bin"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$CAPNP_INSTALL/lib"

mkdir out/$OUT_DIR
sudo chmod 777 out/$OUT_DIR
cp /media/data1/zfk/Documents/sanchecker/src/out/Bytecode/args.gn out/$OUT_DIR/args.gn
echo "gn gen in processing ... "
/media/data1/zfk/Documents/depot_tools/gn gen out/$OUT_DIR
#cd out/$OUT_DIR
echo "ninja clean in processing ... "
/media/data1/zfk/Documents/depot_tools/ninja -C out/$OUT_DIR -t clean
echo "ninja chrome in processing"
/media/data1/zfk/Documents/depot_tools/ninja -C out/$OUT_DIR chrome

