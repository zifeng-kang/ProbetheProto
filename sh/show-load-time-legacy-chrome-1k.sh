#out/Bytecode/chrome $URL --js-flags="--taint_log_file=/media/data1/zfk/Documents/sanchecker/crawl/testpath --no-crankshaft --no-turbo --no-ignition" --no-sandbox --disable-hang-monitor -enable-nacl&>log_file

#usage: sudo bash show-load-time-ndss18-1k.sh 0 1000 2 15

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/media/data1/zfk/Documents/capnproto-install/lib
export SAVE_PATH=/home/zfk/Documents/sanchecker

start_line=$1
end_line=$2
if_flush=$3 # 1 for flush in path TAG="", 0 for flush in path TAG=<self_defined>, other for not flush
#sleep_time=$4
max_num_window=$4

echo "Cleaning cache and tmp ... "
rm -rf ~/.cache/chromium ~/.config/chromium
rm -rf /tmp/*_com /tmp/*_net /tmp/*_org /tmp/*_io /tmp/*_edu /tmp/*_cn /tmp/*_uk
cd ${SAVE_PATH}/src
if ((if_flush == 1))
then
        rm -rf ../crawl && mkdir ../crawl
        rm -rf logs && mkdir logs
        TAG=""
else
        TAG="show_load_time_legacy_chrome_1k_"
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
cd /home/zfk/Downloads/chrome-linux

while IFS=, read -r idx url
do
    if (( idx > $start_line && idx <= $end_line ))
    then
            url="${url//[$'\t\r\n ']}" #remove newline from string
            NAME="${url/./_}"
            echo "${idx} ${url} ${TAG}logs/${NAME}_log_file sanchecker/${TAG}crawl/$NAME"
            ./chrome ${url}/?KEY1[KEY2]=VALUE\&KEY1.KEY2=VALUE\&KEY1[KEY2][KEY3]=VALUE \
                     --user-data-dir=/tmp/${TAG}_${NAME} --load-extension=/home/zfk/Documents/process-cookies/taintchrome/show_load_time_extension --new-window --disable-gpu --no-sandbox --disable-hang-monitor --enable-logging=stderr &>${SAVE_PATH}/src/${TAG}logs/${NAME}_log_file & #& pkill chrome > /dev/null &  #&>logs/${NAME}_log_file &
            #--user-data-dir=/tmp/${NAME}

            if (( (idx - ($start_line)) % $max_num_window == 0 ))
            then
                    echo "Waiting to clean $idx and prev $max_num_window windows ... "
                    # timeout 60 out/Bytecode/chrome $url --js-flags="--taint_log_file=/media/data1/zfk/Documents/sanchecker/${TAG}crawl/$NAME --no-crankshaft --no-turbo --no-ignition" \
                    # --new-window --no-sandbox --disable-hang-monitor -incognito -enable-nacl &>${TAG}logs/${NAME}_log_file && pkill chrome
                    sleep 60s
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
            sleep 60s
            pkill chrome
            echo "All windows cleaned!"
            #echo "Finished and keep the windows to see if anything killed ... "
	    break
    fi
done < <(grep . ${SAVE_PATH}/src/tranco_3Z3L_1k.csv) 
