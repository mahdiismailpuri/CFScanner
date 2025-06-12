#!/bin.bash -
#===============================================================================
# REQUIREMENTS: getopt, jq, git, tput, bc, curl, parallel (version > 20220515), shuf
# ORGANIZATION: Linux
#===============================================================================

# --- Script Version ---
SCRIPT_VERSION="1.7.1-PreserveOrder" # Now preserves original file order in IP mode

# --- Clear Screen ---
clear

echo "CFScanner Version: $SCRIPT_VERSION"
echo "==================================="
echo ""

export TOP_PID=$$

# Function fncFormatSecondsToMmSs
# Converts total seconds to MmSs format (e.g., 90 -> 1m30s)
fncFormatSecondsToMmSs() {
    local total_seconds=$1
    if ! [[ "$total_seconds" =~ ^[0-9]+$ ]] || [[ "$total_seconds" -lt 0 ]]; then
        echo "?m?s"
        return
    fi
    local minutes=$((total_seconds / 60))
    local seconds_part=$((total_seconds % 60))
    printf "%dm%02ds" "$minutes" "$seconds_part"
}
# End of Function fncFormatSecondsToMmSs

# Function fncLongIntToStr
# converts IP in long integer format to a string
fncLongIntToStr() {
    local IFS=. num quad ip e
    num=$1
    for e in 3 2 1
    do
        (( quad = 256 ** e))
        (( ip[3-e] = num / quad ))
        (( num = num % quad ))
    done
    ip[3]=$num
    echo "${ip[*]}"
}
# End of Function fncLongIntToStr

# Function fncIpToLongInt
# converts IP to long integer
fncIpToLongInt() {
    local IFS=. ip num e
    # shellcheck disable=SC2206
    ip=($1)
    for e in 3 2 1
    do
        (( num += ip[3-e] * 256 ** e ))
    done
    (( num += ip[3] ))
    echo $num
}
# End of Function fncIpToLongInt

# Function fncSubnetToIP
# converts subnet to IP list
fncSubnetToIP() {
    # shellcheck disable=SC2206
    local network_arg=$1
    # shellcheck disable=SC2206
    local network_parts=(${network_arg//\// })
    # shellcheck disable=SC2206
    local iparr=(${network_parts[0]//./ })
    local mask=32
    [[ $((${#network_parts[@]})) -gt 1 ]] && mask=${network_parts[1]}

    local maskarr
    # shellcheck disable=SC2206
    if [[ ${mask} = '\.' ]]; then   # already mask format like 255.255.255.0
        maskarr=(${mask//./ })
    else                            # assume CIDR like /24, convert to mask
        if [[ $((mask)) -lt 8 ]]; then
            maskarr=($((256-2**(8-mask))) 0 0 0)
        elif    [[ $((mask)) -lt 16 ]]; then
            maskarr=(255 $((256-2**(16-mask))) 0 0)
        elif    [[ $((mask)) -lt 24 ]]; then
            maskarr=(255 255 $((256-2**(24-mask))) 0)
        elif [[ $((mask)) -lt 32 ]]; then
            maskarr=(255 255 255 $((256-2**(32-mask))))
        elif [[ ${mask} == 32 ]]; then
            maskarr=(255 255 255 255)
        else
            return 1 # Invalid mask
        fi
    fi

    # correct wrong subnet masks (e.g. 240.192.255.0 to 255.255.255.0)
    [[ ${maskarr[2]} == 255 ]] && maskarr[1]=255
    [[ ${maskarr[1]} == 255 ]] && maskarr[0]=255

    local bytes=(0 0 0 0)
    for i in $(seq 0 $((255-maskarr[0]))); do
        bytes[0]="$(( i+(iparr[0] & maskarr[0]) ))"
        for j in $(seq 0 $((255-maskarr[1]))); do
            bytes[1]="$(( j+(iparr[1] & maskarr[1]) ))"
            for k in $(seq 0 $((255-maskarr[2]))); do
                bytes[2]="$(( k+(iparr[2] & maskarr[2]) ))"
                for l in $(seq 0 $((255-maskarr[3]))); do
                    bytes[3]="$(( l+(iparr[3] & maskarr[3]) ))"
                    printf "%d.%d.%d.%d\n" "${bytes[@]}"
                done
            done
        done
    done
}
# End of Function fncSubnetToIP

# Function fncShowProgress (for overall package progress)
function fncShowProgress {
    local barCharDone="=" barCharTodo=" " barSplitter='>' barPercentageScale=2
    local current_pkg="$1" total_pkgs="$2" barSize="10"
    local percent
    if [[ $total_pkgs -eq 0 ]]; then
        percent=0
    else
        percent=$(bc <<< "scale=$barPercentageScale; 100 * $current_pkg / $total_pkgs" )
    fi
    local done_chars=$(bc <<< "scale=0; $barSize * $percent / 100" )
    local todo_chars=$(bc <<< "scale=0; $barSize - $done_chars")
    local doneSubBar=$(printf "%${done_chars}s" | tr " " "${barCharDone}")
    local todoSubBar=$(printf "%${todo_chars}s" | tr " " "${barCharTodo}")

    if [[ $done_chars -ge $barSize ]]; then
        progressBar="Overall Pkgs: [${doneSubBar}] ${percent}%"
    else
        progressBar="Progress bar of main IPs: [${doneSubBar}${barSplitter}${todoSubBar}] ${percent}%"
    fi
}
# End of Function showProgress

# Function fncCheckIPList
function fncCheckIPList {
    local ipList_str="${1}"
    local -a ipList
    IFS=$'\n' read -r -d '' -a ipList < <(printf '%s\n' "$ipList_str" && printf '\0')

    local resultFile="$CF_RESULT_FILE_ARG"; local scriptDir="$CF_SCRIPT_DIR_ARG"
    local configId="$CF_CONFIGID_ARG"; local configHost="$CF_CONFIGHOST_ARG"
    local configPort="$CF_CONFIGPORT_ARG"; local configPath_esc="$CF_CONFIGPATH_ESC_ARG"
    local actual_sni_to_use="$CF_ACTUAL_SNI_ARG" # SNI to use (from ClientConfig: serverName or host)
    local v2rayCommandToRun="$CF_V2RAY_COMMAND_ARG"
    local fileSize="$CF_FILESIZE_ARG"; local tryCount="$CF_TRYCOUNT_ARG"
    local downThreshold="$CF_DOWNTHRESHOLD_ARG"; local upThreshold="$CF_UPTHRESHOLD_ARG"
    local downloadOrUpload="$CF_DOWNLOADORUPLOAD_ARG"; local vpnOrNot="$CF_VPNORNOT_ARG"
    local quickOrNot="$CF_QUICKORNOT_ARG"; local skipPortCheck="$CF_SKIPPORTCHECK_ARG"
    local timeoutCommand domainFronting downOK upOK
    local binDir="$scriptDir/../bin"; local tempConfigDir="$scriptDir/tempConfig"
    local uploadFile="$tempConfigDir/upload_file"; timeoutCommand="timeout"

    if [[ "$vpnOrNot" == "YES" ]]; then
        for ip in "${ipList[@]}"; do
            if [[ -z "$ip" ]]; then continue; fi

            if [[ "$downloadOrUpload" == "BOTH" ]]; then downOK="NO"; upOK="NO";
            elif [[ "$downloadOrUpload" == "UP" ]]; then downOK="YES"; upOK="NO";
            elif [[ "$downloadOrUpload" == "DOWN" ]]; then downOK="NO"; upOK="YES"; fi

            if [[ "$skipPortCheck" == "YES" ]] || $timeoutCommand 1 bash -c "</dev/tcp/$ip/443" > /dev/null 2>&1; then
                if [[ "$quickOrNot" == "NO" ]]; then domainFronting=$($timeoutCommand 1 curl -k -s --tlsv1.2 -H "Host: speed.cloudflare.com" --resolve "speed.cloudflare.com:443:$ip" "https://speed.cloudflare.com/__down?bytes=10");
                else domainFronting="0000000000"; fi

                if [[ "$domainFronting" == "0000000000" ]]; then
                    local ipConfigFile ipO1 ipO2 ipO3 ipO4 port pid

                    ipConfigFile="$tempConfigDir/$ip.config.json"
                    cp "$scriptDir"/config.json.temp "$ipConfigFile"
                    ipO1=$(echo "$ip" | awk -F '.' '{print $1}'); ipO2=$(echo "$ip" | awk -F '.' '{print $2}'); ipO3=$(echo "$ip" | awk -F '.' '{print $3}'); ipO4=$(echo "$ip" | awk -F '.' '{print $4}')
                    port=$((ipO1 + ipO2 + ipO3 + ipO4))
                    local socks_port="3$port"

                    sed -i "s/IP.IP.IP.IP/$ip/g" "$ipConfigFile"; sed -i "s/PORTPORT/$socks_port/g" "$ipConfigFile"
                    sed -i "s/IDID/$configId/g" "$ipConfigFile"; sed -i "s/HOSTHOST/$configHost/g" "$ipConfigFile"
                    sed -i "s/CFPORTCFPORT/$configPort/g" "$ipConfigFile"; sed -i "s|ENDPOINTENDPOINT|$configPath_esc|g" "$ipConfigFile"
                    sed -i "s/RANDOMHOST/$actual_sni_to_use/g" "$ipConfigFile"

                    pid=$(ps aux | grep "config.json.$ip" | grep -v grep | awk '{ print $2 }')
                    if [[ "$pid" ]]; then kill -9 "$pid" > /dev/null 2>&1; fi

                    local downTotalTime=0 upTotalTime=0 downIndividualTimes="" upIndividualTimes="" downSuccessedCount=0 upSuccessedCount=0 downTimeMil upTimeMil result i

                    local v2ray_exec_log_file="$tempConfigDir/v2ray_exec_log.$ip.txt"
                    > "$v2ray_exec_log_file"
                    nohup "$binDir"/"$v2rayCommandToRun" -c "$ipConfigFile" >> "$v2ray_exec_log_file" 2>&1 &
                    local v2ray_pid=$!
                    sleep 2

                    if ! ps -p $v2ray_pid > /dev/null 2>&1; then
                        echo -e "${RED}V2RAY_START_FAILED${NC} $ip (Log: $v2ray_exec_log_file)"
                        if [[ -s "$v2ray_exec_log_file" ]]; then
                            echo "--- V2Ray Log for $ip ---"; cat "$v2ray_exec_log_file"; echo "-------------------------"
                        else
                            echo "V2Ray log file is empty or not created ($v2ray_exec_log_file)."
                        fi
                        continue
                    fi

                    for i in $(seq 1 "$tryCount"); do
                        downTimeMil=0; upTimeMil=0
                        if [[ "$downloadOrUpload" == "DOWN" ]] || [[ "$downloadOrUpload" == "BOTH" ]]; then
                            downTimeMil=$($timeoutCommand 2 curl -x "socks5://127.0.0.1:$socks_port" -s -w "TIME: %{time_total}\n" --resolve "speed.cloudflare.com:443:$ip" "https://speed.cloudflare.com/__down?bytes=$fileSize" --output /dev/null | grep "TIME" | tail -n 1 | awk '{print $2}' | xargs -I {} echo "{} * 1000 /1" | bc )
                            if [[ $downTimeMil -gt 100 ]]; then downSuccessedCount=$((downSuccessedCount+1)); downIndividualTimes+="$downTimeMil, "; else downTimeMil=0; downIndividualTimes+="0, "; fi
                        fi
                        if [[ "$downloadOrUpload" == "UP" ]] || [[ "$downloadOrUpload" == "BOTH" ]]; then
                            result=$($timeoutCommand 2 curl -x "socks5://127.0.0.1:$socks_port" -s -w "\nTIME: %{time_total}\n" --resolve "speed.cloudflare.com:443:$ip" --data "@$uploadFile" https://speed.cloudflare.com/__up | grep "TIME" | tail -n 1 | awk '{print $2}' | xargs -I {} echo "{} * 1000 /1" | bc)
                            if [[ "$result" ]]; then upTimeMil="$result"; if [[ $upTimeMil -gt 100 ]]; then upSuccessedCount=$((upSuccessedCount+1)); upIndividualTimes+="$upTimeMil, "; else upTimeMil=0; upIndividualTimes+="0, "; fi
                            else upIndividualTimes+="0, "; fi
                        fi
                        downTotalTime=$((downTotalTime+downTimeMil)); upTotalTime=$((upTotalTime+upTimeMil))
                    done
                    downIndividualTimes=${downIndividualTimes%, }; upIndividualTimes=${upIndividualTimes%, }
                    local downRealTime=0 upRealTime=0
                    if [[ $downSuccessedCount -ge $downThreshold ]] && [[ "$downloadOrUpload" != "UP" ]]; then downOK="YES"; if [[ $downSuccessedCount -gt 0 ]]; then downRealTime=$((downTotalTime/downSuccessedCount)); fi; fi
                    if [[ $upSuccessedCount -ge $upThreshold ]] && [[ "$downloadOrUpload" != "DOWN" ]]; then upOK="YES"; if [[ $upSuccessedCount -gt 0 ]]; then upRealTime=$((upTotalTime/upSuccessedCount)); fi; fi

                    if kill -0 $v2ray_pid > /dev/null 2>&1; then
                        kill -9 "$v2ray_pid" > /dev/null 2>&1
                    fi

                    if [[ "$downOK" == "YES" ]] && [[ "$upOK" == "YES" ]]; then
                        if [[ "$downRealTime" && $downRealTime -gt 100 ]] || [[ "$upRealTime" && $upRealTime -gt 100 ]]; then
                            echo -e "${GREEN}OK${NC} $ip ${BLUE}DOWN: Avg $downRealTime [$downIndividualTimes] ${ORANGE}UP: Avg $upRealTime [$upIndividualTimes]${NC}"
                            if [[ "$downRealTime" && $downRealTime -gt 100 ]]; then echo "$downRealTime, [$downIndividualTimes] DOWN FOR IP $ip" >> "$resultFile"; fi
                            if [[ "$upRealTime" && $upRealTime -gt 100 ]]; then echo "$upRealTime, [$upIndividualTimes] UP FOR IP $ip" >> "$resultFile"; fi
                        else echo -e "${RED}FAILED${NC} $ip"; fi
                    else echo -e "${RED}FAILED${NC} $ip"; fi
                else echo -e "${RED}FAILED${NC} $ip"; fi
            else echo -e "${RED}FAILED (Port Closed)${NC} $ip"; fi
        done
    elif [[ "$vpnOrNot" == "NO" ]]; then
        for ip in "${ipList[@]}"; do
            if [[ -z "$ip" ]]; then continue; fi
            if [[ "$downloadOrUpload" == "BOTH" ]]; then downOK="NO"; upOK="NO";
            elif [[ "$downloadOrUpload" == "UP" ]]; then downOK="YES"; upOK="NO";
            elif [[ "$downloadOrUpload" == "DOWN" ]]; then downOK="NO"; upOK="YES"; fi

            if [[ "$skipPortCheck" == "YES" ]] || $timeoutCommand 1 bash -c "</dev/tcp/$ip/443" > /dev/null 2>&1; then
                if [[ "$quickOrNot" == "NO" ]]; then domainFronting=$($timeoutCommand 1 curl -k -s --tlsv1.2 -H "Host: speed.cloudflare.com" --resolve "speed.cloudflare.com:443:$ip" "https://speed.cloudflare.com/__down?bytes=10");
                else domainFronting="0000000000"; fi
                if [[ "$domainFronting" == "0000000000" ]]; then
                    local downTotalTime=0 upTotalTime=0 downIndividualTimes="" upIndividualTimes="" downSuccessedCount=0 upSuccessedCount=0 downTimeMil upTimeMil result i
                    for i in $(seq 1 "$tryCount"); do
                        downTimeMil=0; upTimeMil=0
                        if [[ "$downloadOrUpload" == "DOWN" ]] || [[ "$downloadOrUpload" == "BOTH" ]]; then
                            downTimeMil=$($timeoutCommand 2 curl -s -w "TIME: %{time_total}\n" -H "Host: speed.cloudflare.com" --resolve "speed.cloudflare.com:443:$ip" "https://speed.cloudflare.com/__down?bytes=$fileSize" --output /dev/null | grep "TIME" | tail -n 1 | awk '{print $2}' | xargs -I {} echo "{} * 1000 /1" | bc )
                            if [[ $downTimeMil -gt 100 ]]; then downSuccessedCount=$((downSuccessedCount+1)); downIndividualTimes+="$downTimeMil, "; else downTimeMil=0; downIndividualTimes+="0, "; fi
                        fi
                        if [[ "$downloadOrUpload" == "UP" ]] || [[ "$downloadOrUpload" == "BOTH" ]]; then
                            result=$($timeoutCommand 2 curl -s -w "\nTIME: %{time_total}\n" -H "Host: speed.cloudflare.com" --resolve "speed.cloudflare.com:443:$ip" --data "@$uploadFile" https://speed.cloudflare.com/__up | grep "TIME" | tail -n 1 | awk '{print $2}' | xargs -I {} echo "{} * 1000 /1" | bc)
                            if [[ "$result" ]]; then upTimeMil="$result"; if [[ $upTimeMil -gt 100 ]]; then upSuccessedCount=$((upSuccessedCount+1)); upIndividualTimes+="$upTimeMil, "; else upTimeMil=0; upIndividualTimes+="0, "; fi
                            else upIndividualTimes+="0, "; fi
                        fi
                        downTotalTime=$((downTotalTime+downTimeMil)); upTotalTime=$((upTotalTime+upTimeMil))
                    done
                    downIndividualTimes=${downIndividualTimes%, }; upIndividualTimes=${upIndividualTimes%, }
                    local downRealTime=0 upRealTime=0
                    if [[ $downSuccessedCount -ge $downThreshold ]] && [[ "$downloadOrUpload" != "UP" ]]; then downOK="YES"; if [[ $downSuccessedCount -gt 0 ]]; then downRealTime=$((downTotalTime/downSuccessedCount)); fi; fi
                    if [[ $upSuccessedCount -ge $upThreshold ]] && [[ "$downloadOrUpload" != "DOWN" ]]; then upOK="YES"; if [[ $upSuccessedCount -gt 0 ]]; then upRealTime=$((upTotalTime/upSuccessedCount)); fi; fi
                    if [[ "$downOK" == "YES" ]] && [[ "$upOK" == "YES" ]]; then
                        if [[ "$downRealTime" && $downRealTime -gt 100 ]] || [[ "$upRealTime" && $upRealTime -gt 100 ]]; then
                            echo -e "${GREEN}OK${NC} $ip ${BLUE}DOWN: Avg $downRealTime [$downIndividualTimes] ${ORANGE}UP: Avg $upRealTime [$upIndividualTimes]${NC}"
                            if [[ "$downRealTime" && $downRealTime -gt 100 ]]; then echo "$downRealTime, [$downIndividualTimes] DOWN FOR IP $ip" >> "$resultFile"; fi
                            if [[ "$upRealTime" && $upRealTime -gt 100 ]]; then echo "$upRealTime, [$upIndividualTimes] UP FOR IP $ip" >> "$resultFile"; fi
                        else echo -e "${RED}FAILED${NC} $ip"; fi
                    else echo -e "${RED}FAILED${NC} $ip"; fi
                else echo -e "${RED}FAILED${NC} $ip"; fi
            else echo -e "${RED}FAILED (Port Closed)${NC} $ip"; fi
        done
    fi
}
export -f fncCheckIPList fncFormatSecondsToMmSs

fncCheckDpnd() {
    command -v jq >/dev/null 2>&1 || { echo >&2 "jq required"; kill -s 1 "$TOP_PID"; }
    command -v parallel >/dev/null 2>&1 || { echo >&2 "parallel required"; kill -s 1 "$TOP_PID"; }
    command -v bc >/dev/null 2>&1 || { echo >&2 "bc required"; kill -s 1 "$TOP_PID"; }
    command -v timeout >/dev/null 2>&1 || { echo >&2 "timeout required"; kill -s 1 "$TOP_PID"; }
    command -v grep >/dev/null 2>&1 || { echo >&2 "grep required"; kill -s 1 "$TOP_PID"; }
    command -v sort >/dev/null 2>&1 || { echo >&2 "sort required"; kill -s 1 "$TOP_PID"; }
    command -v wc >/dev/null 2>&1 || { echo >&2 "wc required"; kill -s 1 "$TOP_PID"; }
    command -v awk >/dev/null 2>&1 || { echo >&2 "awk required"; kill -s 1 "$TOP_PID"; }
    echo "Linux"
}

fncValidateConfig() {
    local cfg_path="$1";
    if [[ -f "$cfg_path" ]]; then
        echo "reading config ..."
        configId=$(jq --raw-output .id "$cfg_path")
        configHost=$(jq --raw-output .host "$cfg_path")
        configPort=$(jq --raw-output .port "$cfg_path")
        configPath=$(jq --raw-output .path "$cfg_path")
        configServerName_FromFile=$(jq --raw-output .serverName "$cfg_path")
        if [[ "$configServerName_FromFile" == "null" || -z "$configServerName_FromFile" ]]; then
            configServerName_FromFile="$configHost"
        fi

        if ! [[ "$configId" && "$configHost" && "$configPort" && "$configPath" ]]; then
            echo "config invalid (missing id, host, port, or path)"
            exit 1
        fi
    else
        echo "config file $cfg_path not exist"
        exit 1
    fi
}

fncCreateDir() { if [ ! -d "$1" ]; then mkdir -p "$1"; fi; }

function fncRankResults {
    local result_file="$1"
    
    if [ ! -s "$result_file" ]; then
        echo "Result file is empty. No ranking to display."
        return
    fi

    local consolidated_data
    consolidated_data=$(awk '
    BEGIN { FS = "[,[:space:]]+" }
    !/^#/ {
        ip = $NF;
        type = $(NF-3);
        avg_time = $1;
        
        success_count = 0;
        match($0, /\[([^\]]+)\]/, arr);
        split(arr[1], times, /[, ]+/);
        for (i in times) {
            if (times[i] > 0) {
                success_count++;
            }
        }

        if (type == "DOWN") {
            down_avg[ip] = avg_time;
            down_success[ip] = success_count;
        } else if (type == "UP") {
            up_avg[ip] = avg_time;
            up_success[ip] = success_count;
        }
        
        if (!seen[ip]++) {
            ips[++ip_count] = ip;
        }
    }
    END {
        for (i = 1; i <= ip_count; i++) {
            ip = ips[i];
            
            d_avg = (ip in down_avg) ? down_avg[ip] : 0;
            u_avg = (ip in up_avg) ? up_avg[ip] : 0;
            d_succ = (ip in down_success) ? down_success[ip] : 0;
            u_succ = (ip in up_success) ? up_success[ip] : 0;
            
            total_success = d_succ + u_succ;
            combined_time = d_avg + u_avg;
            
            print total_success, combined_time, ip, d_avg, u_avg, d_succ, u_succ;
        }
    }' "$result_file")

    if [ -z "$consolidated_data" ]; then
        echo "No valid results found to rank."
        return
    fi
    
    local sorted_data
    sorted_data=$(echo "$consolidated_data" | sort -k1,1nr -k2,2n)
    
    echo ""
    echo "--- Final Ranking (Best to Worst) ---"
    printf "%-18s | %-15s | %-15s | %-10s | %-10s | %-12s | %-12s\n" "IP_Address" "Total_Success" "Combined_Time" "Down_Avg" "Up_Avg" "D_Success" "U_Success"
    echo "----------------------------------------------------------------------------------------------------------------"
    
    echo "$sorted_data" | while read -r total_succ combined_time ip d_avg u_avg d_succ u_succ; do
        printf "%-18s | %-15s | %-15s | %-10s | %-10s | %-12s | %-12s\n" "$ip" "$total_succ" "$combined_time" "$d_avg" "$u_avg" "$d_succ" "$u_succ"
    done
    echo "----------------------------------------------------------------------------------------------------------------"
}


function runScan {
    local threads="$1" resultFile="$3" scriptDir="$4" \
          configId="$5" configHost="$6" configPort="$7" configPath="$8" \
          fileSize="$9" osVersion="${10}" inputFile="${11}" \
          mode="${12}"

    export CF_RESULT_FILE_ARG="$resultFile"
    export CF_SCRIPT_DIR_ARG="$scriptDir"
    export CF_CONFIGID_ARG="$configId"
    export CF_CONFIGHOST_ARG="$configHost"
    export CF_CONFIGPORT_ARG="$configPort"
    local configPath_esc
    configPath_esc=$(echo "$configPath" | sed 's/\//\\\//g')
    export CF_CONFIGPATH_ESC_ARG="$configPath_esc"
    export CF_FILESIZE_ARG="$fileSize"
    export CF_OS_VERSION_ARG="$osVersion"
    export CF_V2RAY_COMMAND_ARG="v2ray"
    export CF_TRYCOUNT_ARG="$tryCnt_def"
    export CF_DOWNTHRESHOLD_ARG="$downThr_def"
    export CF_UPTHRESHOLD_ARG="$upThr_def"
    export CF_DOWNLOADORUPLOAD_ARG="$dlUl_def"
    export CF_VPNORNOT_ARG="$vpn_def"
    export CF_QUICKORNOT_ARG="$quick_def"
    export CF_SKIPPORTCHECK_ARG="$skipPortCheck_def"
    export CF_ACTUAL_SNI_ARG="$configServerName_FromFile"

    if [[ "$mode" == "SUBNET" ]]; then
        fncMainCFFindSubnet "$threads" "$inputFile"
    elif [[ "$mode" == "IP" ]]; then
        fncMainCFFindIP "$threads" "$inputFile"
    fi
}

fncMainCFFindSubnet() {
    local th_main="$1" subnetsFile_main="$2"
    local parallelVer; parallelVer=$(parallel --version | head -n1 | grep -Ewo '[0-9]{8}')

    echo "Reading subnets from file $subnetsFile_main"
    local cfSubnetList; cfSubnetList=$(cat "$subnetsFile_main")

    echo "Cleaning up the input file to extract valid IP ranges..."
    cfSubnetList=$(echo "$cfSubnetList" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}')
    local count
    count=$(echo "$cfSubnetList" | wc -w)
    echo "$count valid IP ranges extracted."

    local maxSubnet_loop=22
    local all_processing_packages=()
    local ips_in_each_package_array=()
    local total_individual_ips_to_scan=0

    local sn_loop brk_sn_loop nw_loop nm_loop i_lp brk_sn_item_lp temp_arr_calc item_calc ip_list_for_count num_ips_in_package
    echo "Calculating total IPs and preparing packages..."
    for sn_loop in ${cfSubnetList}; do
        brk_sn_loop=""; nw_loop=${sn_loop%/*}; nm_loop=${sn_loop#*/}
        if [[ -z "$nw_loop" || -z "$nm_loop" ]]; then continue; fi
        if [[ ${nm_loop} -ge ${maxSubnet_loop} ]]; then
            brk_sn_loop="${brk_sn_loop} ${nw_loop}/${nm_loop}"
        else
            for i_lp in $(seq 0 $(( $(( 2 ** (maxSubnet_loop - nm_loop) )) - 1 )) ); do
                brk_sn_loop="${brk_sn_loop} $( fncLongIntToStr $(( $( fncIpToLongInt "${nw_loop}" ) + $(( 2 ** ( 32 - maxSubnet_loop ) * i_lp )) )) )/${maxSubnet_loop}"
            done
        fi
        brk_sn_loop=$(echo "${brk_sn_loop}" | sed 's/^ *//;s/ *$//' | tr ' ' '\n')
        if [[ -n "$brk_sn_loop" ]]; then
            IFS=$'\n' read -r -d '' -a temp_arr_calc < <(printf '%s\n' "$brk_sn_loop" && printf '\0')
            for item_calc in "${temp_arr_calc[@]}"; do
                if [[ -n "$item_calc" ]]; then
                    all_processing_packages+=("$item_calc")
                    ip_list_for_count=$(fncSubnetToIP "$item_calc")
                    num_ips_in_package=$(echo -n "$ip_list_for_count" | grep -c '^')
                    ips_in_each_package_array+=("$num_ips_in_package")
                    total_individual_ips_to_scan=$((total_individual_ips_to_scan + num_ips_in_package))
                fi
            done
        fi
    done

    local ipListLength=${#all_processing_packages[@]}
    if [[ $ipListLength -eq 0 ]]; then
        echo "No processable subnets found in the file."
        return
    fi
    echo "Total IP packages to process (y): $ipListLength"
    echo "Total individual IPs to scan: $total_individual_ips_to_scan"

    local start_time_overall=$(date +%s)
    local scanned_individual_ips_count=0
    local current_package_idx ipList_current_pkg_str x_display z_formatted_time

    for (( current_package_idx=0; current_package_idx<ipListLength; current_package_idx++ )); do
        local breakedSubnet_item_current="${all_processing_packages[$current_package_idx]}"
        x_display=$((current_package_idx + 1))

        z_formatted_time="?m?s"
        if [[ $scanned_individual_ips_count -gt 0 ]]; then
            local current_time_for_eta=$(date +%s)
            local elapsed_time_overall=$((current_time_for_eta - start_time_overall))

            if [[ $elapsed_time_overall -gt 0 ]]; then
                local avg_time_per_ip_raw
                avg_time_per_ip_raw=$(bc <<< "scale=4; $elapsed_time_overall / $scanned_individual_ips_count")
                local remaining_individual_ips=$((total_individual_ips_to_scan - scanned_individual_ips_count))
                if [[ $remaining_individual_ips -lt 0 ]]; then remaining_individual_ips=0; fi

                if (( $(echo "$avg_time_per_ip_raw > 0" | bc -l) )); then
                    local eta_seconds_overall_raw
                    eta_seconds_overall_raw=$(bc <<< "scale=0; $avg_time_per_ip_raw * $remaining_individual_ips / 1")
                    z_formatted_time=$(fncFormatSecondsToMmSs "$eta_seconds_overall_raw")
                fi
            fi
        fi

        fncShowProgress "$current_package_idx" "$ipListLength"
        ipList_current_pkg_str=$(fncSubnetToIP "$breakedSubnet_item_current")
        tput cuu1; tput ed

        if [[ $parallelVer -gt 20220515 ]]; then
            parallel --ll --bar -j "$th_main" fncCheckIPList ::: "$ipList_current_pkg_str"
        else
            echo -e "${RED}| ($x_display:$ipListLength=${z_formatted_time}) | $progressBar${NC}"
            parallel -j "$th_main" fncCheckIPList ::: "$ipList_current_pkg_str"
        fi

        local num_ips_in_just_processed_package=${ips_in_each_package_array[$current_package_idx]}
        scanned_individual_ips_count=$((scanned_individual_ips_count + num_ips_in_just_processed_package))
    done

    if [[ $ipListLength -gt 0 ]]; then echo ""; fi
}

fncMainCFFindIP() {
    local threads_ip="$1" ipFile_main="$2"
    local parallelVer; parallelVer=$(parallel --version | head -n1 | grep -Ewo '[0-9]{8}')

    echo "Reading IPs from file $ipFile_main"
    
    # --- MODIFIED: Use awk to de-duplicate and preserve order ---
    local rawIPList; rawIPList=$(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$ipFile_main")
    local total_count; total_count=$(echo "$rawIPList" | wc -l)
    local cfIPList; cfIPList=$(echo "$rawIPList" | awk '!seen[$0]++')
    local unique_count; unique_count=$(echo "$cfIPList" | wc -l)
    local duplicates_removed=$((total_count - unique_count))

    if [[ $duplicates_removed -gt 0 ]]; then
        echo "$duplicates_removed duplicate IPs were found and removed."
    fi
    echo "$unique_count unique IPs will be scanned."
    # --- END MODIFIED ---

    tput cuu1; tput ed
    if [[ $parallelVer -gt 20220515 ]];
    then
      parallel --ll --bar -j "$threads_ip" fncCheckIPList ::: "$cfIPList"
    else
      echo -e "${RED}Scanning IPs...${NC}"
      parallel -j "$threads_ip" fncCheckIPList ::: "$cfIPList"
    fi
}


# --- Main script execution ---
subnetIPFile="NULL"; downThr_def="1"; upThr_def="1"; osVer_glob="$(fncCheckDpnd)"
vpn_def="NO"; dlUl_def="BOTH"; th_def="4"; tryCnt_def="1"; cfg_param="NULL"
speed_param="100"; quick_def="NO"; subnetOrIP_def="SUBNET"; skipPortCheck_def="NO"

configId=""; configHost=""; configPort=""; configPath=""; configServerName_FromFile=""

parsedArgs=$(getopt -a -n cfScanner -o v:m:t:p:n:c:s:d:u:f:q:k:h --long vpn-mode:,mode:,test-type:,thread:,tryCount:,config:,speed:,down-threshold:,up-threshold:,file:,quick:,skip-port-check:,help -- "$@")
eval set -- "$parsedArgs"
while : ; do case "$1" in
    -v|--vpn-mode) vpn_def="$2";shift 2;;
    -m|--mode) subnetOrIP_def="$2";shift 2;;
    -t|--test-type) dlUl_def="$2";shift 2;;
    -p|--thread) th_def="$2";shift 2;;
    -n|--tryCount) tryCnt_def="$2";shift 2;;
    -c|--config) cfg_param="$2";shift 2;;
    -s|--speed) speed_param="$2";shift 2;;
    -d|--down-threshold) downThr_def="$2";shift 2;;
    -u|--up-threshold) upThr_def="$2";shift 2;;
    -f|--file) subnetIPFile="$2";shift 2;;
    -q|--quick) quick_def="$2";shift 2;;
    -k|--skip-port-check) skipPortCheck_def="$2";shift 2;;
    -h|--help) fncUsage;;
    --) shift;break;;
    *) echo "Opt err: $1";fncUsage;; esac
done

# --- Validate arguments ---
if [[ "$vpn_def" != "YES" && "$vpn_def" != "NO" ]]; then echo "Err -v: Must be YES or NO"; exit 2; fi
if [[ "$subnetOrIP_def" != "SUBNET" && "$subnetOrIP_def" != "IP" ]]; then echo "Err -m: Must be SUBNET or IP"; exit 2; fi
if [[ "$dlUl_def" != "DOWN" && "$dlUl_def" != "UP" && "$dlUl_def" != "BOTH" ]]; then echo "Err -t: Must be DOWN, UP, or BOTH"; exit 2; fi
if [[ "$skipPortCheck_def" != "YES" && "$skipPortCheck_def" != "NO" ]]; then echo "Err -k: Must be YES or NO"; exit 2; fi
if [[ "$subnetIPFile" == "NULL" ]] || [[ ! -f "$subnetIPFile" ]]; then echo "Err -f: File not provided or not found"; exit 1; fi

# --- Setup directories and files ---
now=$(date +"%Y%m%d-%H%M%S"); scrDir_glob=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
resDir_glob="$scrDir_glob/result"; resFile_glob="$resDir_glob/$now-result.cf"
tmpCfgDir_glob="$scrDir_glob/tempConfig"; uplFile_glob="$tmpCfgDir_glob/upload_file"

export GREEN='\033[0;32m'; export BLUE='\033[0;34m'; export RED='\033[0;31m'
export ORANGE='\033[0;33m'; export YELLOW='\033[1;33m'; export NC='\033[0m'
fncCreateDir "${resDir_glob}"; fncCreateDir "${tmpCfgDir_glob}";

# --- Create result file with header ---
header1="# Scan Mode: -v $vpn_def"
header2="# Port 443 Check: ENABLED"
if [[ "$skipPortCheck_def" == "YES" ]]; then
    header2="# Port 443 Check: SKIPPED"
fi

if ! { echo "$header1"; echo "$header2"; } > "$resFile_glob" 2>/dev/null; then
    echo "Error: Cannot write to result file '$resFile_glob'. Permission denied or path issue."
    resFile_glob="./$now-result.cf"
    echo "Attempting to write result file to current directory: $resFile_glob"
    if ! { echo "$header1"; echo "$header2"; } > "$resFile_glob"; then
        echo "Error: Still cannot write result file. Please check permissions."
        exit 1
    fi
fi

if [[ "$cfg_param" == "NULL" ]] || [[ ! -f "$cfg_param" ]]; then echo "Err -c"; exit 1;
else echo ""; echo "using config $cfg_param"; cat "$cfg_param"; echo ""; fi

fncValidateConfig "$cfg_param"

fSizeTest_glob="$(( 2 * 100 * 1024 ))"
if [[ "$dlUl_def" == "DOWN" ]] || [[ "$dlUl_def" == "BOTH" ]]; then echo "Testing download: $fSizeTest_glob B"; fi
if [[ "$dlUl_def" == "UP" ]] || [[ "$dlUl_def" == "BOTH" ]]; then
    echo "Testing upload"; echo "Upload file: $fSizeTest_glob B in $uplFile_glob"
    ddSizeForUl="$(( fSizeTest_glob / 1024 ))"; if [[ $ddSizeForUl -eq 0 ]]; then ddSizeForUl=1; fi
    dd if=/dev/random of="$uplFile_glob" bs=1024 count="$ddSizeForUl" > /dev/null 2>&1
fi

# --- Main Logic Branch ---
echo "Mode: $subnetOrIP_def"
runScan "$th_def" "" "$resFile_glob" "$scrDir_glob" \
    "$configId" "$configHost" "$configPort" "$configPath" \
    "$fSizeTest_glob" "$osVer_glob" "$subnetIPFile" "$subnetOrIP_def"

echo ""; echo "Scan complete. Results saved in: $resFile_glob"

# --- Final Ranking ---
fncRankResults "$resFile_glob"
