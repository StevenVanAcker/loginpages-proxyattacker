#!/usr/bin/env python

import subprocess, os, time, signal, urllib, logging, sys, os.path, json
from collections import defaultdict

SINGLE_TIMEOUT = 120
STARTPORT = 10000
PORTDIRFMT = "/tmp/mitmports/{}" # fill in port
INPUTFILEFMT = "/usr/src/inputdata/{}/output.json" # fill in domain

models = ["a1", "a2", "a3", "a1ca", "a2ca", "god"]

def getFreePort(): #{{{
    while True:
        for p in range(STARTPORT, STARTPORT + 5000):
            try:
                os.makedirs(PORTDIRFMT.format(p))
                logging.debug("Running on port {}".format(p))
                return p
            except:
                pass
        time.sleep(1) # if everything is allocated, wait a bit and try the entire range again. This should never have to happen
    return None
#}}}
def freePort(p): #{{{
    try:
        os.rmdir(PORTDIRFMT.format(p))
        logging.debug("Removed port {}".format(p))
    except:
        pass
#}}}
def singleAttack(model, domain): #{{{
    # where is the input data?
    # launch both processes in parallel
    processes = []

    # make sure input exists
    inputfile = INPUTFILEFMT.format(domain)
    if not os.path.exists(inputfile):
        logging.error("Input file {} doesn't exist".format(inputfile))
        sys.exit(1)

    # allocate port for proxy
    port = getFreePort()

    # start proxy
    proxypid = subprocess.Popen("mitmdump -p {} -t . -s '/usr/src/loginpages-proxyattacker/attacker.py {} {}'".format(port, model, domain), shell=True, preexec_fn=os.setsid)

    # wait a couple seconds for it to start
    time.sleep(3)

    # start visitor
    visitorpid = subprocess.Popen("xvfb-run python3 /usr/src/jaek/crawler/attackvisit.py {} {} {} {}".format(model, domain, inputfile, port), shell=True, preexec_fn=os.setsid)

    # wait...
    finished = False
    deadline = time.time() + SINGLE_TIMEOUT
    while not finished and time.time() < deadline:
        time.sleep(1)
        finished = not visitorpid.poll() is None

    # kill visitor
    try:
        os.killpg(os.getpgid(visitorpid.pid), signal.SIGKILL)
        logging.info("Had to kill visitor")
    except:
        pass

    # dump record
    proxies = {'http': 'http://localhost:{}'.format(port)}
    urllib.urlopen("http://dumprecord/", proxies=proxies)

    # kill proxy
    try:
        os.killpg(os.getpgid(proxypid.pid), signal.SIGKILL)
        logging.info("Killed proxy")
    except:
        pass

    # release port proxy
    freePort(port)
#}}}
def makeHistogram(d): #{{{
    out = defaultdict(int)
    for l in d:
        out[l] += 1

    return dict(out)
#}}}
def combineSingleModelData(am): #{{{
    output = {}

    try:
        # if a2, a2ca or a3 attackermodel is used, check for bamc/uir/sri
        fixdata = False
        if am in ["a2", "a2ca", "a3"]:
            fixdata = True

        visitorfile = "visitor-output-{}.json".format(am)
        proxyfile = "mitmproxy-output-{}.json".format(am)

        vdata = json.load(open(visitorfile))
        pdata = json.load(open(proxyfile))

        for url, rec in pdata["urls"].items():
            # for each proxied URL:
            #    was it protected by BAMC/UIR/SRI?
            #    what was the type?
            #    was there an attack?

            # redirectPageResources is a dict with url keys and dict values
            matchedresources = []
            bamc = False
            uir = False
            sri = False

            for mainurl, rec2 in vdata["redirectPageResources"].items():
                for rectype, rec3 in rec2.items():
                    if type(rec3) == dict:
                        for suburl, subrec in rec3.items():
                            myrec = dict(subrec)
                            myrec["rectype"] = rectype
                            myrec["parentpage"] = mainurl
                            bamc |= myrec["bamc"]
                            sri |= myrec["sri"]
                            uir |= myrec["uir"]
                            if suburl == url:
                                matchedresources += [myrec]


            # alerts is just an array with records
            matchedalerts = []
            for x in vdata["alerts"]:
                if x["resource"] == url:
                    # if the attack was a success, but BAMC/UIR/SRI was set, consider it a failed attack and log the reason
                    if fixdata and "notfoiled" in x and (bamc or uir or sri):
                        del x["notfoiled"]
                        x["foiled"] = "BAMC/SRI/UIR set to {}/{}/{}".format(bamc, sri, uir)
                    matchedalerts += [x]

            rec["matchedResources"] = matchedresources
            rec["matchedAlerts"] = matchedalerts
        pdata["pwfields"] = vdata["pwfields"]
        output = pdata
    except:
        pass
    return output
#}}}
def combineAllModelData(): #{{{
    models = ["a1", "a2", "a3", "a1ca", "a2ca", "god"]
    modelsData = {}
    for m in models:
        cd = combineSingleModelData(m)
                
        modelsData[m] = {}
        if cd == {}:
            continue

        # total amount of resources seen, this included those that fail outside the attacker model (e.g. not in the domain)
        modelsData[m]["requestsSeen"] = len(cd["urls"])
        # total amount of injected resources that are also sensitive
        modelsData[m]["redirectHijacks"] = len([u for u,x in cd["urls"].items() if "hijackedRedirect" in x and x["hijackedRedirect"]])
        # reasons why we could/couldn't inject in those resources that were in scope (e.g. in the correct domain, but HTTPS used for a1)
        injectionSuccessReasons = [x["notfoiled"] for u,x in cd["urls"].items() if "notfoiled" in x]
        injectionFailReasons = [x["foiled"] for u,x in cd["urls"].items() if "foiled" in x]
        injectionSuccessReasonsDict = makeHistogram(injectionSuccessReasons)
        injectionFailReasonsDict = makeHistogram(injectionFailReasons)
        modelsData[m]["requestsInScope"] = len(injectionSuccessReasons + injectionFailReasons)
        modelsData[m]["proxyInjectReasons"] = {
            "success": injectionSuccessReasonsDict,
            "failed": injectionFailReasonsDict
        }

        # total amount of injected resources that succeeded in stealing pw
        modelsData[m]["requestsAttacked"] = defaultdict(int)
        for (u,x) in [(u,x) for (u,x) in cd["urls"].items() if "injected" in x and "notfoiled" in x]:
            modelsData[m]["requestsAttacked"]["total"] += 1
            for rt in x["injected"].keys():
                modelsData[m]["requestsAttacked"][rt] += 1

        modelsData[m]["succeededAttacks"] = defaultdict(int)
        for (u,x) in [(u,x) for (u,x) in cd["urls"].items() if "injected" in x and "notfoiled" in x and "matchedAlerts" in x and len(x["matchedAlerts"]) > 0]:
            modelsData[m]["succeededAttacks"]["total"] += 1
            for rt in x["injected"].keys():
                modelsData[m]["succeededAttacks"][rt] += 1

        ### special case for CSS: if any password fields are tainted, we consider that a successful CSS attack
        # check if any password fields are tainted
        tainted = any([x["taintedCSS"] for x in cd["pwfields"]])
        ### if any tainted: add number of CSS requestedAttacks to succeededAttacks
        if tainted and "CSS" in modelsData[m]["requestsAttacked"].keys():
            modelsData[m]["succeededAttacks"]["CSS"] += modelsData[m]["requestsAttacked"]["CSS"]
            modelsData[m]["succeededAttacks"]["total"] += modelsData[m]["requestsAttacked"]["CSS"]

        # check the form target
        modelsData[m]["formtargetNotHTTPS"] = False
        modelsData[m]["formtargetNotSameDomain"] = False
        for x in cd["pwfields"]:
            try:
                formurl = x["formTarget"]
                urlparts = urlparse(formurl)
                if not ("." + urlparts.hostname.lower()).endswith("." + domain.lower()):
                    modelsData[m]["formtargetNotSameDomain"] = True
                if urlparts.scheme.lower() != "https":
                    modelsData[m]["formtargetNotHTTPS"] = True
            except:
                pass

    return modelsData
#}}}

if __name__ == "__main__":
    domain = sys.argv[1]
    for m in models:
        singleAttack(m, domain)
        success = True
        for f in ["visitor-output-{}.json".format(m), "mitmproxy-output-{}.json".format(m)]:
            if not os.path.exists(f):
                success = False

        if not success:
            singleAttack(m, domain)

    json.dump(combineAllModelData(), open("output.json", "w"))
