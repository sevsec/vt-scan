#!/bin/bash
# Current functionality:
#  - Submit a file object to be scanned by VT
#  - Retrieve a scan report from VT
VERSION="1.0 (December 3rd, 2019)"

check_deps() {
    if ! [[ -f /usr/bin/curl ]]; then
        echo -ne "You are missing curl, which is required to run this script. Please install curl and try again.\n\n"
        exit 126
    elif ! [[ -f /usr/bin/jq ]]; then
        echo -ne "You are missing jq, which is required to run this script. Please install jq and try again.\n\n"
        exit 127
    fi
}

write_usage() {
    # output script purpose, params
    echo "VirusTotal Scan Script - $VERSION"
    echo -ne "Submit a file object to VirusTotal for analysis.\n\n"
    echo -ne "Required parameters: API token, file path.\n"
    echo -ne "Usage: ./vt-scan.sh -t <API TOKEN> -f <FILE PATH>\n\n"
    echo -ne "\t-t\t\tAPI Token for VirusTotal (required).\n"
    echo -ne "\t-f\t\tFull path(?) to file object for VT to scan.\n"
    echo -ne "\t-o\t\tSave VT output to a file (optional).\n"
    echo -ne "\t-r\t\tGet report on a resource that has been scanned (optional).\n"
    echo -ne "\t\t\t(Note: enabling this will supercede a scan request.)\n"
    echo -ne "\t-v\t\tDisplay version information.\n"
    echo -ne "\t-h\t\tDisplay this help text with usage information.\n\n"
}

vt_scan() {
    APIKEY="$1"
    FILE="$2"
    curl -s --request POST --url "https://www.virustotal.com/vtapi/v2/file/scan" --form "apikey=$APIKEY" --form "file=@$FILE"
}

vt_report() {
    APIKEY="$1"
    RESOURCE="$2"
    curl -s --request GET --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=$APIKEY&resource=$RESOURCE"
}
# Make sure we have the necessary dependencies
check_deps

# Grab CLI options
while getopts ":t:f:v:h:o:r:" FLAG; do
    case $FLAG in
        t) #API Token
            if [[ "$OPTARG" =~ [0-9a-z]{64} ]]; then
                APIKEY="$OPTARG"
            else
                echo "Invalid API key: $OPTARG"
                exit 2
            fi;;
        f) # File and file path
            if [[ -f "$OPTARG" ]]; then
                FILE="$OPTARG"
            else
                echo "Invalid file specified: $OPTARG"
                exit 3
            fi;;
        o) # Output from VT
            OUTFILE="$OPTARG";;
        r)
            RESOURCE="$OPTARG";;
        v) # Display version information
            echo $VERSION
            exit 0;;
        h) # Help
            write_usage
            exit 0;;
        *) # Missing option
            echo "ERROR: missing an option."
            write_usage
            exit 1;;
        :) # Missing argument
            echo "ERROR: missing an argument."
            write_usage
            exit 1;;
        \?) # Unknown option
            echo "ERROR: Unknown argument/option."
            write_usage
            exit 1;;
    esac
done
shift "$((OPTIND-1))"

# If we don't have the require params, throw an error
if [[ $APIKEY ]] && [[ $RESOURCE ]]; then
    # If we have an API token and a report ID, silently curl
    RESULTS=$(vt_report "$APIKEY" "$RESOURCE")

    if [[ -n $OUTFILE ]]; then
        echo $RESULTS | jq '.' | cat > $OUTFILE
    fi

    echo $RESULTS | jq
elif [[ $APIKEY ]] && [[ $FILE ]]; then
    # If we have an API token and a file, silently curl
    RESULTS=$(vt_scan "$APIKEY" "$FILE")

    if [[ -n $OUTFILE ]]; then
        echo $RESULTS | jq '.' | cat > $OUTFILE
    fi

    echo $RESULTS | jq
else
    echo -ne "Either you did not give the required parameters or you wish to do nothing. So be it.\n\n"
    write_usage
fi
