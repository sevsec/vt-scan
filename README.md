# vt-scan: VirusTotal Scan Script  
Simple bash script that allows you to either submit a file object for scan by VirusTotal or retrieve a report from a VirusTotal scan.  


Why bash? Because it's easily available on most Linux boxes and doesn't require installing a separate interpreter or additional overhead (libraries, smaller footprint).  


For the record, I'm sure similar projects already exist, but since I quickly created this out of necessity, I figured that I'd share it anyway.  

## Requirements  
This is a bash script, so the requirements are:  
    * bash  
    * curl  
    * jq  

This script also requires that you supply your own API token for VT. You may sign up for VT (and then generate a token) here: https://www.virustotal.com/gui/join-us.  

## Usage  
VirusTotal Scan Script for API V3  
Interact with VT from your shell.  
  
Required parameters: API token, Action to perform.  
Usage example: ./vt-scan.sh -t <API TOKEN> -f <FILE PATH>  

	-k		API key for VirusTotal - REQUIRED.  
	-f		FULL PATH to a file object for VT to scan.  
	-u		Submit URL for VT scan.  
	-d		Submit domain for VT scan.  
	-i		Submit IP for VT scan.  
	-a		Retrieve analysis for existing scan, expects base64 object ID.  
	-v		Display version information.  
	-h		Display this help text with usage information.  
  
## TODO:  
* Allow reading API token from local file (e.g. .vtscan/token)  
* Integrate additional public APIs from VT  
* Integrate addition private APIs from VT  
* Pretty-print output formatting; human-readable terminal output  
