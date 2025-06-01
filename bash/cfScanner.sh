#!/binbash -
#===============================================================================
# REQUIREMENTS: getopt, jq, git, tput, bc, curl, parallel (version > 20220515), shuf
# ORGANIZATION: Linux
#===============================================================================

# --- Script Version ---
SCRIPT_VERSION="1.1.1" # Incremented version

# --- Clear Screen ---
clear

echo "CFScanner Version: $SCRIPT_VERSION"
echo "==================================="
echo ""

export TOP_PID=$$

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
  local network=(${1//\// })
    # shellcheck disable=SC2206
  local iparr=(${network[0]//./ })
  local mask=32
  [[ $((${#network[@]})) -gt 1 ]] && mask=${network[1]}

  local maskarr
    # shellcheck disable=SC2206
  if [[ ${mask} = '\.' ]]; then  # already mask format like 255.255.255.0
    maskarr=(${mask//./ })
  else                           # assume CIDR like /24, convert to mask
    if [[ $((mask)) -lt 8 ]]; then
      maskarr=($((256-2**(8-mask))) 0 0 0)
    elif  [[ $((mask)) -lt 16 ]]; then
      maskarr=(255 $((256-2**(16-mask))) 0 0)
    elif  [[ $((mask)) -lt 24 ]]; then
      maskarr=(255 255 $((256-2**(24-mask))) 0)
    elif [[ $((mask)) -lt 32 ]]; then
      maskarr=(255 255 255 $((256-2**(32-mask))))
    elif [[ ${mask} == 32 ]]; then
      maskarr=(255 255 255 255)
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
          for l in $(seq 1 $((255-maskarr[3]))); do 
            bytes[3]="$(( l+(iparr[3] & maskarr[3]) ))"
            printf "%d.%d.%d.%d\n" "${bytes[@]}"
          done
        done
      done
    done
}
# End of Function fncSubnetToIP

# Function fncShowProgress
function fncShowProgress {
    barCharDone="="
    barCharTodo=" "
    barSplitter='>'
    barPercentageScale=2
  current="$1"
  total="$2"
  barSize="10" 

  percent=$(bc <<< "scale=$barPercentageScale; 100 * $current / $total" )
  done=$(bc <<< "scale=0; $barSize * $percent / 100" )
  todo=$(bc <<< "scale=0; $barSize - $done")
  doneSubBar=$(printf "%${done}s" | tr " " "${barCharDone}")
  todoSubBar=$(printf "%${todo}s" | tr " " "${barCharTodo} - 1") 
  spacesSubBar=$(printf "%${todo}s" | tr " " " ")

  # This global variable will be passed to parallel
  progressBar="| Progress bar of main IPs: [${doneSubBar}${barSplitter}${todoSubBar}] ${percent}%${spacesSubBar}" 
}
# End of Function showProgress

# Function fncCheckIPList
function fncCheckIPList {
    local ipList # received_progressBar_string (arg2) is not used for logic here
    ipList="${1}"
    # Arguments previously passed directly are now read from environment variables
    local resultFile="$CF_RESULT_FILE_ARG"
    local scriptDir="$CF_SCRIPT_DIR_ARG"
    local configId="$CF_CONFIGID_ARG"
    local configHost="$CF_CONFIGHOST_ARG"
    local configPort="$CF_CONFIGPORT_ARG"
    local configPath_esc="$CF_CONFIGPATH_ESC_ARG" # Using escaped version
    local fileSize="$CF_FILESIZE_ARG"
    # local osVersion="$CF_OS_VERSION_ARG" # "Linux", not directly used by name in this function
    # local v2rayCommand="$CF_V2RAY_COMMAND_ARG" # "v2ray", not directly used by name
    local tryCount="$CF_TRYCOUNT_ARG"
    local downThreshold="$CF_DOWNTHRESHOLD_ARG"
    local upThreshold="$CF_UPTHRESHOLD_ARG"
    local downloadOrUpload="$CF_DOWNLOADORUPLOAD_ARG"
    local vpnOrNot="$CF_VPNORNOT_ARG"
    local quickOrNot="$CF_QUICKORNOT_ARG"

    local timeoutCommand domainFronting downOK upOK
    local binDir="$scriptDir/../bin"
    local tempConfigDir="$scriptDir/tempConfig"
    local uploadFile="$tempConfigDir/upload_file" # Uses scriptDir from env
    
    timeoutCommand="timeout"

    if [[ "$vpnOrNot" == "YES" ]]
    then
        for ip in ${ipList}
            do
                if [[  "$downloadOrUpload" == "BOTH" ]]; then downOK="NO"; upOK="NO";
                elif [[ "$downloadOrUpload" == "UP" ]]; then downOK="YES"; upOK="NO";
                elif [[ "$downloadOrUpload" == "DOWN" ]]; then downOK="NO"; upOK="YES"; fi

                if $timeoutCommand 1 bash -c "</dev/tcp/$ip/443" > /dev/null 2>&1;
                then
                    if [[ "$quickOrNot" == "NO" ]]; then
                        domainFronting=$($timeoutCommand 1 curl -k -s --tlsv1.2 -H "Host: speed.cloudflare.com" --resolve "speed.cloudflare.com:443:$ip" "https://speed.cloudflare.com/__down?bytes=10")
                    else
                        domainFronting="0000000000"
                    fi

                    if [[ "$domainFronting" == "0000000000" ]]; then
                        local mainDomain randomUUID configServerName ipConfigFile ipO1 ipO2 ipO3 ipO4 port pid
                        mainDomain=$(echo "$configHost" | awk -F '.' '{ print $2"."$3}')
                        randomUUID=$(cat /proc/sys/kernel/random/uuid)
                        configServerName="$randomUUID.$mainDomain"
                        ipConfigFile="$tempConfigDir/config.json.$ip"
                        cp "$scriptDir"/config.json.temp "$ipConfigFile"
                        ipO1=$(echo "$ip" | awk -F '.' '{print $1}'); ipO2=$(echo "$ip" | awk -F '.' '{print $2}'); ipO3=$(echo "$ip" | awk -F '.' '{print $3}'); ipO4=$(echo "$ip" | awk -F '.' '{print $4}')
                        port=$((ipO1 + ipO2 + ipO3 + ipO4))
                        
                        sed -i "s/IP.IP.IP.IP/$ip/g" "$ipConfigFile"
                        sed -i "s/PORTPORT/3$port/g" "$ipConfigFile"
                        sed -i "s/IDID/$configId/g" "$ipConfigFile"
                        sed -i "s/HOSTHOST/$configHost/g" "$ipConfigFile"
                        sed -i "s/CFPORTCFPORT/$configPort/g" "$ipConfigFile"
                        sed -i "s/ENDPOINTENDPOINT/$configPath_esc/g" "$ipConfigFile" # Use escaped
                        sed -i "s/RANDOMHOST/$configServerName/g" "$ipConfigFile"
                        
                        pid=$(ps aux | grep "config.json.$ip" | grep -v grep | awk '{ print $2 }')
                        if [[ "$pid" ]]; then kill -9 "$pid" > /dev/null 2>&1; fi
                        
                        local downTotalTime=0 upTotalTime=0 downIndividualTimes="" upIndividualTimes="" downSuccessedCount=0 upSuccessedCount=0 downTimeMil upTimeMil result i
                        nohup "$binDir"/"v2ray" -c "$ipConfigFile" > /dev/null & 
                        sleep 2
                        for i in $(seq 1 "$tryCount"); do
                            downTimeMil=0; upTimeMil=0
                            if [[ "$downloadOrUpload" == "DOWN" ]] || [[ "$downloadOrUpload" == "BOTH" ]]; then
                                downTimeMil=$($timeoutCommand 2 curl -x "socks5://127.0.0.1:3$port" -s -w "TIME: %{time_total}\n" --resolve "speed.cloudflare.com:443:$ip" "https://speed.cloudflare.com/__down?bytes=$fileSize" --output /dev/null | grep "TIME" | tail -n 1 | awk '{print $2}' | xargs -I {} echo "{} * 1000 /1" | bc )
                                if [[ $downTimeMil -gt 100 ]]; then downSuccessedCount=$((downSuccessedCount+1)); downIndividualTimes+="$downTimeMil, "; else downTimeMil=0; downIndividualTimes+="0, "; fi
                            fi
                            if [[ "$downloadOrUpload" == "UP" ]] || [[ "$downloadOrUpload" == "BOTH" ]]; then
                                result=$($timeoutCommand 2 curl -x "socks5://127.0.0.1:3$port" -s -w "\nTIME: %{time_total}\n" --resolve "speed.cloudflare.com:443:$ip" --data "@$uploadFile" https://speed.cloudflare.com/__up | grep "TIME" | tail -n 1 | awk '{print $2}' | xargs -I {} echo "{} * 1000 /1" | bc)
                                if [[ "$result" ]]; then upTimeMil="$result"; if [[ $upTimeMil -gt 100 ]]; then upSuccessedCount=$((upSuccessedCount+1)); upIndividualTimes+="$upTimeMil, "; else upTimeMil=0; upIndividualTimes+="0, "; fi
                                else upIndividualTimes+="0, "; fi
                            fi
                            downTotalTime=$((downTotalTime+downTimeMil)); upTotalTime=$((upTotalTime+upTimeMil))
                        done
                        downIndividualTimes=${downIndividualTimes%, }; upIndividualTimes=${upIndividualTimes%, }
                        local downRealTime=0 upRealTime=0
                        if [[ $downSuccessedCount -ge $downThreshold ]] && [[ "$downloadOrUpload" != "UP" ]]; then downOK="YES"; if [[ $downSuccessedCount -gt 0 ]]; then downRealTime=$((downTotalTime/downSuccessedCount)); fi; fi
                        if [[ $upSuccessedCount -ge $upThreshold ]] && [[ "$downloadOrUpload" != "DOWN" ]]; then upOK="YES"; if [[ $upSuccessedCount -gt 0 ]]; then upRealTime=$((upTotalTime/upSuccessedCount)); fi; fi
                        
                        pid=$(ps aux | grep "config.json.$ip" | grep -v grep | awk '{ print $2 }')
                        if [[ "$pid" ]]; then kill -9 "$pid" > /dev/null 2>&1; fi

                        if [[ "$downOK" == "YES" ]] && [[ "$upOK" == "YES" ]]; then
                            if [[ "$downRealTime" && $downRealTime -gt 100 ]] || [[ "$upRealTime" && $upRealTime -gt 100 ]]; then
                                echo -e "${GREEN}OK${NC} $ip ${BLUE}DOWN: Avg $downRealTime [$downIndividualTimes] ${ORANGE}UP: Avg $upRealTime [$upIndividualTimes]${NC}"
                                if [[ "$downRealTime" && $downRealTime -gt 100 ]]; then echo "$downRealTime, [$downIndividualTimes] DOWN FOR IP $ip" >> "$resultFile"; fi
                                if [[ "$upRealTime" && $upRealTime -gt 100 ]]; then echo "$upRealTime, [$upIndividualTimes] UP FOR IP $ip" >> "$resultFile"; fi
                            else echo -e "${RED}FAILED${NC} $ip"; fi
                        else echo -e "${RED}FAILED${NC} $ip"; fi
                    else echo -e "${RED}FAILED${NC} $ip"; fi
                else echo -e "${RED}FAILED${NC} $ip"; fi
        done
    elif [[ "$vpnOrNot" == "NO" ]]
    then
        for ip in ${ipList}
            do
                if [[  "$downloadOrUpload" == "BOTH" ]]; then downOK="NO"; upOK="NO";
                elif [[ "$downloadOrUpload" == "UP" ]]; then downOK="YES"; upOK="NO";
                elif [[ "$downloadOrUpload" == "DOWN" ]]; then downOK="NO"; upOK="YES"; fi

                if $timeoutCommand 1 bash -c "</dev/tcp/$ip/443" > /dev/null 2>&1;
                then
                    if [[ "$quickOrNot" == "NO" ]]; then
                        domainFronting=$($timeoutCommand 1 curl -k -s --tlsv1.2 -H "Host: speed.cloudflare.com" --resolve "speed.cloudflare.com:443:$ip" "https://speed.cloudflare.com/__down?bytes=10")
                    else
                        domainFronting="0000000000"
                    fi
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
                else echo -e "${RED}FAILED${NC} $ip"; fi
        done
    fi
}
# End of Function fncCheckIPList
export -f fncCheckIPList

# Function fncCheckDpnd
function fncCheckDpnd {
    command -v jq >/dev/null 2>&1 || { echo >&2 "I require 'jq' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
    command -v parallel >/dev/null 2>&1 || { echo >&2 "I require 'parallel' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
    command -v bc >/dev/null 2>&1 || { echo >&2 "I require 'bc' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
    command -v timeout >/dev/null 2>&1 || { echo >&2 "I require 'timeout' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
    echo "Linux" 
}
# End of Function fncCheckDpnd

# Function fncValidateConfig
function fncValidateConfig {
    local config_file_path="$1" # Renamed to avoid conflict with global 'config'
    if [[ -f "$config_file_path" ]]; then
        echo "reading config ..."
        # These are intended to be global for the script
        configId=$(jq --raw-output .id "$config_file_path")
        configHost=$(jq --raw-output .host "$config_file_path")
        configPort=$(jq --raw-output .port "$config_file_path")
        configPath=$(jq --raw-output .path "$config_file_path")
        if ! [[ "$configId" && "$configHost" && "$configPort" && "$configPath" ]]; then
            echo "config is not correct"
            exit 1
        fi
    else
        echo "config file does not exist $config_file_path"
        exit 1
    fi
}
# End of Function fncValidateConfig

# Function fncCreateDir
function fncCreateDir {
    local dirPath="${1}"
    if [ ! -d "$dirPath" ]; then
        mkdir -p "$dirPath"
    fi
}
# End of Function fncCreateDir

# Function fncMainCFFindSubnet
function fncMainCFFindSubnet {
    # These are arguments passed to this function
    local threads_main="${1}"
    # progressBar_main_arg is arg ${2} - a placeholder now, as global progressBar is used by fncShowProgress
    local resultFile_main="${3}"
    local scriptDir_main="${4}"
    local configId_main="${5}" # This is the global configId set by fncValidateConfig
    local configHost_main="${6}" # This is the global configHost
    local configPort_main="${7}" # This is the global configPort
    local configPath_main="${8}" # This is the global configPath
    local fileSize_main="${9}"
    local osVersion_main_arg="${10}" 
    local subnetsFile_main="${11}"
    local tryCount_main="${12}"
    local downThreshold_main="${13}"
    local upThreshold_main="${14}"
    local downloadOrUpload_main="${15}"
    local vpnOrNot_main="${16}"
    local quickOrNot_main="${17}"

    local v2rayCommand_local="v2ray" 
    local parallelVersion
    parallelVersion=$(parallel --version | head -n1 | grep -Ewo '[0-9]{8}')
    
    # Exporting variables needed by fncCheckIPList
    export CF_RESULT_FILE_ARG="$resultFile_main"
    export CF_SCRIPT_DIR_ARG="$scriptDir_main"
    export CF_CONFIGID_ARG="$configId_main"
    export CF_CONFIGHOST_ARG="$configHost_main"
    export CF_CONFIGPORT_ARG="$configPort_main"
    # configPath_main needs to be escaped for sed in fncCheckIPList
    # It's better to do escaping once before export or handle it carefully.
    # For now, assume fncCheckIPList will handle its own copy or receive it escaped.
    # Let's export the original and an escaped version if needed, or handle in fncCheckIPList.
    # The original script escaped it inside fncCheckIPList. So we pass the original.
    # However, for consistency, we'll pass the escaped version via env var.
    local configPath_main_esc=$(echo "$configPath_main" | sed 's/\//\\\//g')
    export CF_CONFIGPATH_ESC_ARG="$configPath_main_esc"
    
    export CF_FILESIZE_ARG="$fileSize_main"
    export CF_OS_VERSION_ARG="$osVersion_main_arg" # "Linux"
    export CF_V2RAY_COMMAND_ARG="$v2rayCommand_local" # "v2ray"
    export CF_TRYCOUNT_ARG="$tryCount_main"
    export CF_DOWNTHRESHOLD_ARG="$downThreshold_main"
    export CF_UPTHRESHOLD_ARG="$upThreshold_main"
    export CF_DOWNLOADORUPLOAD_ARG="$downloadOrUpload_main"
    export CF_VPNORNOT_ARG="$vpnOrNot_main"
    export CF_QUICKORNOT_ARG="$quickOrNot_main"


    if [[ ! -f "$subnetsFile_main" ]] && [[ "$subnetsFile_main" != "NULL" ]]; then
        echo "Subnet file $subnetsFile_main not found. Exiting."
        exit 1
    elif [[ "$subnetsFile_main" == "NULL" ]]; then
        echo "No subnet file provided. Please provide a subnet file using -f option. Exiting."
        exit 1
    fi

    echo "Reading subnets from file $subnetsFile_main"
    local cfSubnetList
    cfSubnetList=$(cat "$subnetsFile_main")
    
    local ipListLength="0"
    local subNet_loop breakedSubnets_loop maxSubnet_loop network_loop netmask_loop i_loop breakedSubnet_item_loop
    for subNet_loop in ${cfSubnetList}
    do
        breakedSubnets_loop= 
        maxSubnet_loop=24 
        network_loop=${subNet_loop%/*}
        netmask_loop=${subNet_loop#*/}
        if [[ ${netmask_loop} -ge ${maxSubnet_loop} ]]; then
          breakedSubnets_loop="${breakedSubnets_loop} ${network_loop}/${netmask_loop}"
        else
          for i_loop in $(seq 0 $(( $(( 2 ** (maxSubnet_loop - netmask_loop) )) - 1 )) ); do
            breakedSubnets_loop="${breakedSubnets_loop} $( fncLongIntToStr $(( $( fncIpToLongInt "${network_loop}" ) + $(( 2 ** ( 32 - maxSubnet_loop ) * i_loop )) )) )/${maxSubnet_loop}"
          done
        fi
        breakedSubnets_loop=$(echo "${breakedSubnets_loop}"|tr ' ' '\n')
        for breakedSubnet_item_loop in ${breakedSubnets_loop} ; do
            ipListLength=$(( ipListLength+1 ))
        done
    done

    local passedIpsCount=0
    local ipList_loop # Renamed to avoid conflict
    # progressBar is a global variable set by fncShowProgress
    for subNet_loop in ${cfSubnetList}
    do
        breakedSubnets_loop=
        maxSubnet_loop=24 
        network_loop=${subNet_loop%/*}
        netmask_loop=${subNet_loop#*/}
        if [[ ${netmask_loop} -ge ${maxSubnet_loop} ]]; then
          breakedSubnets_loop="${breakedSubnets_loop} ${network_loop}/${netmask_loop}"
        else
          for i_loop in $(seq 0 $(( $(( 2 ** (maxSubnet_loop - netmask_loop) )) - 1 )) ); do
            breakedSubnets_loop="${breakedSubnets_loop} $( fncLongIntToStr $(( $( fncIpToLongInt "${network_loop}" ) + $(( 2 ** ( 32 - maxSubnet_loop ) * i_loop )) )) )/${maxSubnet_loop}"
          done
        fi
        breakedSubnets_loop=$(echo "${breakedSubnets_loop}"|tr ' ' '\n')
        for breakedSubnet_item_loop in ${breakedSubnets_loop} ; do
            fncShowProgress "$passedIpsCount" "$ipListLength" # Sets global progressBar
            
            ipList_loop=$(fncSubnetToIP "$breakedSubnet_item_loop")

            tput cuu1; tput ed 

            if [[ $parallelVersion -gt 20220515 ]]; then
              parallel --ll --bar -j "$threads_main" fncCheckIPList ::: "$ipList_loop" ::: "$progressBar"
            else
              echo -e "${RED}$progressBar${NC}" 
              parallel -j "$threads_main" fncCheckIPList ::: "$ipList_loop" ::: "$progressBar"
            fi
            passedIpsCount=$(( passedIpsCount+1 ))
        done
    done
    echo "" 
    sort -n -k1 -t, "$resultFile_main" -o "$resultFile_main"
}
# End of Function fncMainCFFindSubnet

# --- Main script execution ---
subnetIPFile="NULL" 

# Function fncUsage
function fncUsage {
    echo -e "Usage: cfScanner [ -v|--vpn-mode YES/NO ]
            [ -t|--test-type  DOWN/UP/BOTH ]
            [ -p|--thread <int> ]
            [ -n|--tryCount <int> ]
            [ -c|--config <configfile> ]
            [ -s|--speed <int> ]
            [ -d|--down-threshold <int> ]
            [ -u|--up-threshold <int> ]
            [ -f|--file <subnet-range-file> (REQUIRED)]
            [ -q|--quick YES/NO]
            [ -h|--help ]\n"
     exit 2
}
# End of Function fncUsage

downThreshold_default="1"
upThreshold_default="1"
osVersion_global="$(fncCheckDpnd)" 
vpnOrNot_default="NO"
downloadOrUpload_default="BOTH"
threads_default="4"
tryCount_default="1"
config_param="NULL" # Parameter for config file path
speed_param="100" 
quickOrNot_default="NO"

# Global progressBar, will be set by fncShowProgress
progressBar="" 

parsedArguments=$(getopt -a -n cfScanner -o v:t:p:n:c:s:d:u:f:q:h --long vpn-mode:,test-type:,thread:,tryCount:,config:,speed:,down-threshold:,up-threshold:,file:,quick:,help -- "$@")
eval set -- "$parsedArguments"
while : ; do
    case "$1" in
        -v|--vpn-mode) vpnOrNot_default="$2" ; shift 2 ;;
        -t|--test-type) downloadOrUpload_default="$2" ; shift 2 ;;
        -p|--thread) threads_default="$2" ; shift 2 ;;
        -n|--tryCount) tryCount_default="$2" ; shift 2 ;;
        -c|--config) config_param="$2" ; shift 2 ;;
        -s|--speed) speed_param="$2" ; shift 2 ;; 
        -d|--down-threshold) downThreshold_default="$2" ; shift 2 ;;
        -u|--up-threshold) upThreshold_default="$2" ; shift 2 ;;
        -f|--file) subnetIPFile="$2" ; shift 2 ;;
        -q|--quick) quickOrNot_default="$2" ; shift 2 ;;
        -h|--help) fncUsage ;;
        --) shift; break ;;
        *) echo "Unexpected option: $1 is not acceptable"; fncUsage ;;
    esac
done

if [[ "$vpnOrNot_default" != "YES" && "$vpnOrNot_default" != "NO" ]]; then echo "Wrong value for -v: $vpnOrNot_default Must be YES or NO"; exit 2; fi
if [[ "$downloadOrUpload_default" != "DOWN" && "$downloadOrUpload_default" != "UP" && "$downloadOrUpload_default" != "BOTH" ]]; then echo "Wrong value for -t: $downloadOrUpload_default Must be DOWN or UP or BOTH"; exit 2; fi
if [[ "$subnetIPFile" == "NULL" ]] || [[ ! -f "$subnetIPFile" ]]; then echo "Subnet file is required and was not found or not provided. Use -f <filepath>"; exit 1; fi

now=$(date +"%Y%m%d-%H%M%S")
scriptDir_global=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
resultDir_global="$scriptDir_global/result"
resultFile_global="$resultDir_global/$now-result.cf"
tempConfigDir_global="$scriptDir_global/tempConfig"

uploadFile_global="$tempConfigDir_global/upload_file" # Uses tempConfigDir_global

# These will be set by fncValidateConfig using the config_param path
configId=""
configHost=""
configPort=""
configPath=""

export GREEN='\033[0;32m'
export BLUE='\033[0;34m'
export RED='\033[0;31m'
export ORANGE='\033[0;33m'
export YELLOW='\033[1;33m'
export NC='\033[0m' 

fncCreateDir "${resultDir_global}"
fncCreateDir "${tempConfigDir_global}"
echo "" > "$resultFile_global" 

if [[ "$config_param" == "NULL" ]] || [[ ! -f "$config_param" ]]; then
    echo "Config file is required and was not found or not provided. Use -c <filepath>"
    exit 1
else
    echo ""
    echo "using your own config $config_param"
    cat "$config_param"
    echo ""
fi

fncValidateConfig "$config_param" # Sets global configId, configHost, etc.

fileSizeForTest_global="$(( 2 * 100 * 1024 ))" 

if [[ "$downloadOrUpload_default" == "DOWN" ]] || [[ "$downloadOrUpload_default" == "BOTH" ]]; then
    echo "You are testing download with file size: $fileSizeForTest_global Bytes"
fi
if [[ "$downloadOrUpload_default" == "UP" ]] || [[ "$downloadOrUpload_default" == "BOTH" ]]; then
    echo "You are testing upload"
    echo "making upload file by size $fileSizeForTest_global Bytes in $uploadFile_global"
    ddSizeForUpload="$(( fileSizeForTest_global / 1024 ))"
    if [[ $ddSizeForUpload -eq 0 ]]; then ddSizeForUpload=1; fi 
    dd if=/dev/random of="$uploadFile_global" bs=1024 count="$ddSizeForUpload" > /dev/null 2>&1
fi

# Call fncMainCFFindSubnet
# The second argument (old progressBar placeholder) is still passed as per original structure,
# though fncMainCFFindSubnet now uses global progressBar set by fncShowProgress for passing to parallel.
fncMainCFFindSubnet "$threads_default" "$progressBar" "$resultFile_global" "$scriptDir_global" \
    "$configId" "$configHost" "$configPort" "$configPath" \
    "$fileSizeForTest_global" "$osVersion_global" "$subnetIPFile" "$tryCount_default" \
    "$downThreshold_default" "$upThreshold_default" "$downloadOrUpload_default" \
    "$vpnOrNot_default" "$quickOrNot_default"

echo ""
echo "Scan complete. Results are in: $resultFile_global"
