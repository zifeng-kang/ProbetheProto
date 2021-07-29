#out/Bytecode/chrome $URL --js-flags="--taint_log_file=/media/data1/zfk/Documents/sanchecker/crawl/testpath --no-crankshaft --no-turbo --no-ignition" --no-sandbox --disable-hang-monitor -enable-nacl&>log_file

#usage: sudo bash postMessage-auto.sh 0 18 2 1

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/media/data1/zfk/Documents/capnproto-install/lib
export SAVE_PATH=/home/zfk/Documents/sanchecker

start_line=$1
end_line=$2
if_flush=$3 # 1 for flush in path TAG="", 0 for flush in path TAG=<self_defined>, other for not flush
#sleep_time=$4
max_num_window=$4 # suggest: max_num_window=1

rm -rf ~/.cache/chromium ~/.config/chromium
rm -rf /tmp/*_com /tmp/*_net /tmp/*_org /tmp/*_io /tmp/*_edu /tmp/*_cn /tmp/*_site
cd ${SAVE_PATH}/src
if ((if_flush == 1))
then
        rm -rf ../crawl && mkdir -p ../crawl
        rm -rf logs && mkdir -p logs
        TAG=""
else
        # TAG="message_log_0to600kplus_"
        TAG="postMessage_flows_0to1m_" #websites_to_pp_message_0to600kplus.txt
        if ((if_flush == 0))
        then
                rm -rf ../${TAG}crawl && mkdir -p ../${TAG}crawl
                rm -rf ${TAG}logs && mkdir -p ${TAG}logs
	else
		mkdir -p ../${TAG}crawl
                mkdir -p ${TAG}logs
	fi
        
fi

cd /media/data1/zfk/Documents/sanchecker/src

while IFS=, read -r idx url num
do
    if (( idx > $start_line && idx <= $end_line ))
    then
            url="${url//[$'\t\r\n ']}" #remove newline from string
            NAME="${url/https:\/\//}"
            NAME=$(echo $NAME | sed 's/[\/?=".]/_/g')
            echo "${idx} ${url} ${num} ${TAG}logs/${NAME}log_file sanchecker/${TAG}crawl/$NAME"
            out/PP/chrome ${url} --js-flags="--taint_log_file=${SAVE_PATH}/${TAG}crawl/$NAME --no-crankshaft --no-turbo --no-ignition" \
                     --user-data-dir=/tmp/${NAME} --load-extension=/home/zfk/Documents/process-cookies/taintchrome/message_log_extension,/home/zfk/Documents/process-cookies/taintchrome/postMessage_extension,/home/zfk/Documents/process-cookies/taintchrome/pp_check_for_message_extension --new-window --no-sandbox --disable-gpu --disable-hang-monitor -disable-popup-blocking &>${SAVE_PATH}/src/${TAG}logs/${NAME}log_file & #& pkill chrome > /dev/null &  #&>logs/${NAME}_log_file &
            #--user-data-dir=/tmp/${NAME}

            if (( (idx - ($start_line)) % $max_num_window == 0 || idx == $end_line ))
            then
                    echo "Waiting to clean $idx and prev $max_num_window windows ... "
                    # timeout 60 out/Bytecode/chrome $url --js-flags="--taint_log_file=/media/data1/zfk/Documents/sanchecker/${TAG}crawl/$NAME --no-crankshaft --no-turbo --no-ignition" \
                    # --new-window --no-sandbox --disable-hang-monitor -incognito -enable-nacl &>${TAG}logs/${NAME}_log_file && pkill chrome
                    sleep ${num}s
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
            sleep ${num}s
            pkill chrome
            echo "All windows cleaned!"
        #     echo "Finished and keep the windows to see if anything killed ... "
	    break
    fi
done < <(grep . ${SAVE_PATH}/src/msg_origin_to_crawl.txt) #websites_to_pp_message_600kto1m_result_from_key1key2.txt)  # websites_to_pp_message_0to200k.txt
#/media/data1/zfk/Documents/sanchecker/src/recursive_pp_pattern1_rankmorethan10k_logs/websites_to_pp.txt #tranco_94Q2.csv

#export FILE="./logs/${NAME}_log_file"
            #echo "logs/${NAME}_log_file"
            #CMD="out/Bytecode/chrome $url --js-flags=\"--taint_log_file=/media/data1/zfk/Documents/sanchecker/crawl/$NAME --no-crankshaft --no-turbo --no-ignition\" --no-sandbox --disable-hang-monitor -incognito -enable-nacl&>${NAME}_log_file"

#echo $CMD
            #bash -c $CMD
            #screen -S $idx -dm bash -c $CMD

# Now missing:
# 1,https://auth.wistia.com/session/new?app=wistia,1536
# 11,https://flippengroup.com/,1132