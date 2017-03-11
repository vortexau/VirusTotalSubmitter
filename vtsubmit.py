#!/usr/bin/env python

import json
import glob
import hashlib
import os
import json
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = 'INSERT API KEY HERE'

# Public API only gets 4 requsts/minute.
# Sleep for 20 seconds between each request.
# Save last-run to file

# Cowrie DL dir
cowriedir = '/opt/cowrie/dl'
runfile = 'lastrun'

# Setup VT API
vt = VirusTotalPublicApi(API_KEY)

# Last run time
lastrun = os.stat(runfile).st_atime
print "Last access was at {}".format(time.ctime(lastrun))

# Parse all the files in 'dl' since last run date
for (dirpath, dirnames, filenames) in os.walk(cowriedir):
    for file in filenames:
        size = os.path.getsize(cowriedir + "/" + file)
        ctime = os.path.getctime(cowriedir + "/" + file)

        # check if file is newer than last run
        if ctime < lastrun:
            continue

        if size == 0:
            #print file + " zero size"
            continue

        if len(file) != 64:
            continue
        
        # Only the sha256 hashed files exist in the list
        # at this point

        # Example response when file does not exist. JSON
        #{
        #    "response_code": 200,
        #    "results": {
        #        "response_code": 0,
        #        "resource": "784c525b3acdc095c1671470a601e826",
        #        "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
        #    }
        #}
        response = vt.get_file_report(file)
        
	      try:
            if(response['results']['response_code'] == 0):
                print "File " + file + " not known to VirusTotal!"
            	  submitresponse = vt.scan_file(cowriedir + "/" + file, True)
            	  print json.dumps(submitresponse, sort_keys=False, indent=4)
            else:
            	  print "File " + file + " is already known to VirusTotal"
	       except KeyError, e:
	           print "KeyError. reason: %s" % str(e)
	           print "Full Response:"
	           print response

        print "Sleeping for 20 seocnds"
        time.sleep(20)

print "Execution finished. Updating runfile"
with open(runfile, 'a'):
    os.utime(runfile, None)
