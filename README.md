# vt-scan: VirusTotal Scan Script
Simple bash script that allows you to either submit a file object for scan by VirusTotal or retrieve a report from a VirusTotal scan.


Why bash? Because it's easily available on most Linux boxes and doesn't require installing a separate interpreter or additional overhead.
I'm sure this project already exists, but I whipped it up quickly on my own out of necessity.

## Requirements
This is a bash script, so the requirements are:
    * bash
    * curl
    * jq

This script also requires that you supply your own API token for VT. You may sign up for VT (and then generate a token) here: https://www.virustotal.com/gui/join-us.


## TODO:
* Allow reading API token from local file (e.g. .vtscan/token
* Integrate additional public APIs from VT
* Integrate addition private APIs from VT
