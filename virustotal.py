import simplejson
import urllib
import urllib2

rpt_url = "https://www.virustotal.com/vtapi/v2/file/report"
my_key = "8543f7d97ac322569c9f8f87d9a80d5a8623ed1e38429b7d3611d86d5cf46712"


# Grab the report on a specific md5/sha1/sha256 key
def get_virustotal_report(vir_key):
    parameters = {"resource": vir_key,
                  "apikey": my_key}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(rpt_url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    return simplejson.loads(json)




#print(simplejson.dumps(apks, sort_keys=True, indent=4 * ' '))

virus = get_virustotal_report("99017f6eebbac24f351415dd410d522d")
print(virus)