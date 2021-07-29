export OUT_DIR=$1
export PKG_CONFIG_PATH="/media/data1/zfk/Documents/sanchecker/src/build/linux/debian_wheezy_amd64-sysroot/usr/share/pkgconfig"
export CAPNP_INSTALL="/media/data1/zfk/Documents/capnproto-install"
export PATH="/usr/bin:$PATH:$CAPNP_INSTALL/bin"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$CAPNP_INSTALL/lib"

#mkdir out/$OUT_DIR
#cp out/args.gn out/$OUT_DIR/args.gn
#gn gen out/$OUT_DIR
#cd out/$OUT_DIR
echo "ninja clean ... "
/media/data1/zfk/Documents/depot_tools/ninja -C out/$OUT_DIR -t clean
echo "ninja chrome ... "
/media/data1/zfk/Documents/depot_tools/ninja -C out/$OUT_DIR chrome
