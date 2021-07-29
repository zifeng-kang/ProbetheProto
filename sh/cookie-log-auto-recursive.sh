#out/Bytecode/chrome $URL --js-flags="--taint_log_file=/media/data1/zfk/Documents/sanchecker/crawl/testpath --no-crankshaft --no-turbo --no-ignition" --no-sandbox --disable-hang-monitor -enable-nacl&>log_file

#usage: sudo bash cookie-log-auto-recursive.sh 0 100000 2 15

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/media/data1/zfk/Documents/capnproto-install/lib
export SAVE_PATH=/home/zfk/Documents/sanchecker

start_line=$1
end_line=$2
if_flush=$3 # 1 for flush in path TAG="", 0 for flush in path TAG=<self_defined>, other for not flush
#sleep_time=$4
max_num_window=$4

rm -rf ~/.cache/chromium ~/.config/chromium
rm -rf /tmp/*_com /tmp/*_net /tmp/*_org /tmp/*_io /tmp/*_edu /tmp/*_cn /tmp/*_site
cd ${SAVE_PATH}/src
if ((if_flush == 1))
then
        rm -rf ../crawl && mkdir ../crawl
        rm -rf logs && mkdir logs
        TAG=""
else
        TAG="cookie_log_600kto1m_" #cookie_log_0to600kplus_
        if ((if_flush == 0))
        then
                rm -rf ../${TAG}crawl && mkdir ../${TAG}crawl
                rm -rf ${TAG}logs && mkdir ${TAG}logs
	else
		mkdir -p ../${TAG}crawl
                mkdir -p ${TAG}logs
	fi
        
fi

cd /media/data1/zfk/Documents/sanchecker/src

while IFS=, read -r idx url
do
    if (( idx > $start_line && idx <= $end_line ))
    then
            url="${url//[$'\t\r\n ']}" #remove newline from string
            NAME="${url/./_}"
            echo "${idx} ${url} ${TAG}logs/${NAME}_log_file sanchecker/${TAG}crawl/$NAME"
            out/PP/chrome ${url}/ --js-flags="--taint_log_file=${SAVE_PATH}/${TAG}crawl/$NAME --no-crankshaft --no-turbo --no-ignition" \
                     --user-data-dir=/tmp/${NAME} --load-extension=/media/data1/zfk/Documents/crawler-extension-pp,/home/zfk/Documents/process-cookies/taintchrome/cookie_storage_log_extension --new-window --no-sandbox --disable-gpu --disable-hang-monitor &>${SAVE_PATH}/src/${TAG}logs/${NAME}_log_file & #& pkill chrome > /dev/null &  #&>logs/${NAME}_log_file &
            #--user-data-dir=/tmp/${NAME}

            if (( (idx - ($start_line)) % $max_num_window == 0 ))
            then
                    echo "Waiting to clean $idx and prev $max_num_window windows ... "
                    # timeout 60 out/Bytecode/chrome $url --js-flags="--taint_log_file=/media/data1/zfk/Documents/sanchecker/${TAG}crawl/$NAME --no-crankshaft --no-turbo --no-ignition" \
                    # --new-window --no-sandbox --disable-hang-monitor -incognito -enable-nacl &>${TAG}logs/${NAME}_log_file && pkill chrome
                    sleep 180s
                    pkill chrome
                    sleep 3s
                    echo "$idx and prev $max_num_window windows cleaned! "
		    rm -rf /tmp/*_com /tmp/*_net /tmp/*_org /tmp/*_io /tmp/*_edu
            #else
                    
            fi
            #sleep ${sleep_time}s --user-data-dir=/tmp
    elif ((idx > $end_line))
    then
            echo "Come to the end $idx. Waiting to clean all windows ... "
            sleep 120s
            pkill chrome
            echo "All windows cleaned!"
        #     echo "Finished and keep the windows to see if anything killed ... "
	    break
    fi
done < <(grep . ${SAVE_PATH}/src/websites_to_pp_cookie_storage_600kto1m_result_from_key1key2.txt) #websites_to_pp_cookie_storage_0to600kplus.txt) # websites_to_pp_cookie_storage_0to200k.txt
#/media/data1/zfk/Documents/sanchecker/src/recursive_pp_pattern1_rankmorethan10k_logs/websites_to_pp.txt #tranco_94Q2.csv

#export FILE="./logs/${NAME}_log_file"
            #echo "logs/${NAME}_log_file"
            #CMD="out/Bytecode/chrome $url --js-flags=\"--taint_log_file=/media/data1/zfk/Documents/sanchecker/crawl/$NAME --no-crankshaft --no-turbo --no-ignition\" --no-sandbox --disable-hang-monitor -incognito -enable-nacl&>${NAME}_log_file"

#echo $CMD
            #bash -c $CMD
            #screen -S $idx -dm bash -c $CMD
