#!/bin/bash
# Current functionality:
#  - Submit a file object to be scanned by VT
#  - Retrieve a scan report from VT
set -u
set -o pipefail
VERSION="Version 2.1 (April 26, 2021)"

check_deps() {
    # Validate that curl and jq are available
    which curl > /dev/null 2>&1
    if [[ "$?" -ne 0 ]]; then
        echo -ne "You are missing curl, which is required to run this script. Please install curl and try again.\n\n"
        exit 4
    fi

    which jq > /dev/null 2>&1
    if [[ "$?" -ne 0 ]]; then
        echo -ne "You are missing jq, which is required to run this script. Please install jq and try again.\n\n"
        exit 5
    fi
}

write_usage() {
    # output script purpose, params
    echo "VirusTotal Scan Script for API V3"
    echo -ne "Interact with VT from your shell.\n\n"
    echo -ne "Required parameters: API token, Action to perform.\n"
    echo -ne "Usage example: ./vt-scan.sh -k <API TOKEN> -f <FILE PATH>\n\n"
    echo -ne "\t-k\t\tAPI key for VirusTotal - REQUIRED.\n"
    echo -ne "\t-f\t\tFULL PATH to a file object for VT to scan.\n"
    echo -ne "\t-u\t\tSubmit URL for VT scan.\n"
    echo -ne "\t-d\t\tSubmit domain for VT scan.\n"
    echo -ne "\t-i\t\tSubmit IP for VT scan.\n"
    echo -ne "\t-a\t\tRetrieve analysis for existing scan, expects base64 object ID.\n"
    echo -ne "\t-v\t\tDisplay version information.\n"
    echo -ne "\t-h\t\tDisplay this help text with usage information.\n\n"
}

vt_file() {
    # Submit a file
    APIKEY="$1"
    FILE="$2"
    local FSIZE=$(stat $FILE | grep "Size:" | awk '{print $2}')
    if [[ $FSIZE -gt 33554431 ]]; then
      vt_bigfile "$APIKEY" "$FILE"
    else
      curl -s --request POST --url "https://www.virustotal.com/api/v3/files" --header "x-apikey: $APIKEY" --form "file=@$FILE"
    fi
}

vt_bigfile() {
    # files > 32M need a special upload URL
    APIKEY="$1"
    FILE="$2"
    URL=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/files/upload_url" --header "x-apikey: $APIKEY" | jq -r .data)
    curl -s --request POST --url "$URL" --header "x-apikey: $APIKEY" --form "file=@$FILE"
}

vt_url() {
    # Submit a URL
    APIKEY="$1"
    URL="$2"
    curl -s --request GET --url "https://www.virustotal.com/api/v3/urls" --header "x-apikey: $APIKEY" --form "url=$URL"
}

vt_domain() {
    # Submit a domain
    APIKEY="$1"
    DOMAIN="$2"
    curl -s --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN" --header "x-apikey: $APIKEY"
}

vt_ip() {
    # Submit an IP
    APIKEY="$1"
    IP="$2"
    curl -s --request GET --url "https://www.virustotal.com/api/v3/ip_addresses/$IP" --header "x-apikey: $APIKEY"
}

vt_analysis() {
    # Retrieve analysis for a file
    APIKEY="$1"
    FILEID="$2"
    curl -s --request GET --url "https://www.virustotal.com/api/v3/analyses/$FILEID" --header "x-apikey: $APIKEY"
}

vt_report() {
    # Retrieve a report - I believe this is deprecated, leaving in for now
    APIKEY="$1"
    RESOURCE="$2"
    curl -s --request GET --url "https://www.virustotal.com/api/v3/file/report?apikey=$APIKEY&resource=$RESOURCE"
}

##### EXECUTION BEGINS HERE #####
# Make sure we have the necessary dependencies
check_deps

# Grab CLI options
while getopts ":k:a:f:u:d:i:vh:" FLAG; do
    case ${FLAG} in
        k ) #API Token
            if [[ "$OPTARG" =~ [0-9a-z]{64} ]]; then
                APIKEY="$OPTARG"
            else
                echo "Invalid API key: $OPTARG"
                exit 2
            fi
            ;;
        a ) # Retrieve analysis on a file
            FILEID="$OPTARG"
            vt_analysis "$APIKEY" "$FILEID"
            exit 0
            ;;
        f ) # File and file path
            if [[ -f "$OPTARG" ]]; then
                FILE="$OPTARG"
                vt_file "$APIKEY" "$FILE"
            else
                echo "Invalid file specified: $OPTARG"
                exit 3
            fi
            exit 0
            ;;
        u ) # URL
            URL="$OPTARG"
            vt_url "$APIKEY" "$URL"
            exit 0
            ;;
        d ) # Domain
            DOMAIN="$OPTARG"
            vt_domain "$APIKEY" "$DOMAIN"
            exit 0
            ;;
        i ) # IP
            IP="$OPTARG"
            vt_ip "$APIKEY" "$IP"
            exit 0
            ;;
        v ) # Display version information
            echo $VERSION
            exit 0
            ;;
        h | * | \? | :) # Help
            write_usage
            exit 0
            ;;
    esac
done
shift $((OPTIND -1))

echo -ne "Either you did not give the required parameters or you wish to do nothing. So be it.\n\n"
write_usage
