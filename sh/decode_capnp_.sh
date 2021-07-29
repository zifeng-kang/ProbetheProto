# To run: 
# sudo bash decode_capnp_.sh

# TAG="check_pp_pattern1_0to200k_crawl"
# TAG="recursive_pp_pattern1_0to200k_crawl"
#TAG = "recursive_pp_pattern1_0to200k_crawl"
PREFIX="record_"
ROOT="/home/zfk/Documents/sanchecker/"
#mkdir ${ROOT}${PREFIX}'check_pp_pattern1_0to600kplus_crawl'
#mkdir -p ${ROOT}${PREFIX}'new_check_pp_pattern1_0to600kplus_crawl'
mkdir -p ${ROOT}${PREFIX}'check_pp_pattern1_0to1m_crawl'

while IFS=, read -r log_name
do
    # ls -lh '/home/zfk/Documents/sanchecker/check_pp_pattern1_0to600kplus_crawl/'${log_name}
    /media/data1/zfk/Documents/capnproto-install/bin/capnp decode \
    /media/data1/zfk/Documents/sanchecker/src/v8/src/taint_tracking/protos/logrecord.capnp \
    TaintLogRecord < '/home/zfk/Documents/sanchecker/check_pp_pattern1_600kto1m_crawl/'${log_name} > ${ROOT}${PREFIX}'check_pp_pattern1_0to1m_crawl'/${PREFIX}${log_name}
done < '/home/zfk/Documents/sanchecker/src/list_to_capnp_check_pp_pattern1_600kto1m.txt'
#'/home/zfk/Documents/sanchecker/src/vul_to_url_websites_cleaned_0to600kplus.txt'  #list_to_capnp_original_recursive_vul_url_0to200k.txt #list_to_capnp_vul_url_0to200k.txt
# list_to_capnp_recursive_key1key2_600kto1m.txt
# list_to_capnp_check_pp_pattern1_0to600kplus.txt
# 
