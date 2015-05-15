#!/Library/Frameworks/Python.framework/Versions/3.4/bin/python
#note above line is for MacPorts python (with Requests module)
#!/usr/bin/env python3

# This is a simple Collector Program who's intent is to demonstrate how
# we can collect simple Metrics and submit them to CA Wily via
# the RESTful interface that is part of the EPAgent.
#
# This script will collect statistics from docker via the Remote API.
# The statistics are stored under the following groups: Docker
#
# TODO
#       collectDocker:
#           Calls the Docker Remote API an retrieves container statistics.
#
# The metrics will be default be reported under
# 'Docker|Containers|<container>|...'.  As
# multiple hosts can report to a single EPAgent's RESTful interface.  The inclusion
# the <hostname> in the metric path gives a opportunity to disambiguate those
# usages.
#
# Requirements:
#
#   This script requires the 'requests' python package in order to process the
#   RESTful queries.  This can be obtained in one of the following ways:
#
#       # yum install python-requests
#                   or
#       # pip install requests
#                   or
#       # easy_install requests
#
# Usage:
#
#        Usage: docker.py [options]
#
#        Options:
#          -h, --help            show this help message and exit
#          -v, --verbose         verbose output
#          -H HOSTNAME, --hostname=HOSTNAME
#                                hostname EPAgent is running on
#          -p PORT, --port=PORT  port EPAgent is connected to
#          -m METRICPATH, --metric_path=METRICPATH
#                                metric path header for all metrics
#          -d DOCKERHOST, --docker_host=DOCKERHOST
#                                docker hostname
#          -r DOCKERPORT, --docker_port=DOCKERPORT
#                                docker Remote API port
#         -c CERTFILE, --certificate=CERTFILE
#                               https certificate
#         -k KEYFILE, --private_key=KEYFILE
#                               https private key
#


import json
import optparse
import requests
import sys
from datetime import datetime

"""
global dicts for metrics to display
"""

infoMap = { 'Containers'    : ':Container Count',
            'Images'        : ':Image Count',
            'MemTotal'      : ':Total Memory',
            'MemoryLimit'   : ':MemoryLimit',
            'SwapLimit'     : ':SwapLimit' }

containerMap = { 'Image'    : ':Image',
            'SizeRw'        : ':SizeRw',
            'SizeRootFs'    : ':SizeRootFs',
            'Status'        : ':Status' }

statsMap = {'network' : {   'rx_dropped': '|Network|Receive:Dropped',
                            'rx_bytes'  : '|Network|Receive:Bytes',
                            'rx_errors' : '|Network|Receive:Errors',
                            'rx_packets': '|Network|Receive:Packets',
                            'tx_dropped': '|Network|Transmit:Dropped',
                            'tx_bytes'  : '|Network|Transmit:Bytes',
                            'tx_errors' : '|Network|Transmit:Errors',
                            'tx_packets': '|Network|Transmit:Packets'},
            'memory_stats' : {  'max_usage' : '|Memory:Max Usage',
                                'usage'     : '|Memory:Current Usage',
                                'limit'     : '|Memory:Limit',
                                'failcnt'   : '|Memory:Fail Count'},
            'cpu_stats' : { 'system_cpu_usage'  : '|CPU:System (Ticks)',
                            'cpu_usage' : { 'usage_in_usermode' :   '|CPU:User Mode (Ticks)',
                                            'total_usage' :         '|CPU:Total (Ticks)',
                                            'usage_in_kernelmode' : '|CPU:Kernel (Ticks)'}}}


def callUrl(url, certfile, keyfile):
    try:
        response = requests.get(url, cert=(certfile, keyfile))
    except requests.exceptions.SSLError as err:
        print("Unable to connect to docker via URL \"{}\": {}\ncheck certificate!".format(url, err))
        sys.exit(1)

        #print("Unable to connect to docker via URL \"{}\": {}\ncheck URL and port!".format(url, err))
        #sys.exit(1)
    data = response.json()
    #print(json.dumps(data, sort_keys=True, indent=4))
    return data


def streamUrl(url, certfile, keyfile):
    response = requests.get(url, cert=(certfile, keyfile), stream=True)

    for line in response.iter_lines():
        # only read first line
        response.close()
        data = json.loads(line.decode("utf-8"))
        #print(json.dumps(data, sort_keys=True, indent=4))
        return data


def writeMetrics(values, metricPath, metricDict, metricMap):

    for key in values.keys():

        name = metricMap.get(key)

        if name:
            #print('type of {} is {}, name = {}'.format(key, type(values[key]), name))
            #if (type(values[key]) is list):
            #    for entry in values[key]:

            if (type(values[key]) is dict):
                writeMetrics(values[key], metricPath, metricDict, metricMap[key])

            if (type(values[key]) is str):
                m = {}
                m['type'] = 'StringEvent'
                m['name'] = metricPath + '{0}'.format(name)
                m['value']= "{0}".format(values[key])
                metricDict['metrics'].append(m)

            if (type(values[key]) is int):
                # use long if it ends with 'Limit', '(Ticks)' or 'bytes'
                if ((-1 < name.find('Limit', len(name)-5, len(name))) or
                    (-1 < name.find('(Ticks)', len(name)-7, len(name))) or
                    (-1 < name.find('bytes', len(name)-5, len(name)))):
                    m = {}
                    m['type'] = 'LongCounter'
                    m['name'] = metricPath + '{0}'.format(name)
                    m['value']= "{0}".format(values[key])
                    metricDict['metrics'].append(m)
                else:
                    if ((-1 < key.find('Average', 0, 7)) or (-1 < key.find('PercentUsage', len(key)-12, len(key)))):
                        # should be IntPercentage for 'PercentUsage' but this is not a EPA supported metric data type
                        m = {}
                        m['type'] = 'IntAverage'
                        m['name'] = metricPath + '{0}'.format(name)
                        m['value']= "{0}".format(values[key])
                        metricDict['metrics'].append(m)
                    else:
                        m = {}
                        m['type'] = 'IntCounter'
                        m['name'] = metricPath + '{0}'.format(name)
                        m['value']= "{0}".format(values[key])
                        metricDict['metrics'].append(m)

            if (type(values[key]) is bool):
                if (-1 == key.find('Limit', len(key)-5, len(key))):
                    m = {}
                    m['type'] = 'IntAverage'
                    m['name'] = metricPath + '{0}'.format(name)
                    if (values[key]):
                        m['value']= '1'
                    else:
                        m['value']= '0'
                    metricDict['metrics'].append(m)

            if (type(values[key]) is float):
                m = {}
                m['type'] = 'IntCounter'
                m['name'] = metricPath + '{0}'.format(name)
                m['value']= "{0}".format(int(float(values[key] + .5)))
                metricDict['metrics'].append(m)



def collectDocker(metricDict, metricPath, dockerhost, dockerport, certfile, keyfile):

    """
    Get docker system wide information
    """

    url = "https://{0}:{1}/info".format(dockerhost, dockerport)
    data = callUrl(url, certfile, keyfile)
    #print(json.dumps(data, sort_keys=True, indent=4))
    writeMetrics(data, metricPath, metricDict, infoMap)


    """
    Conversion of docker statistics data into metrics to be harvested
    """

    url = "https://{0}:{1}/containers/json?size=1".format(dockerhost, dockerport)
    data = callUrl(url, certfile, keyfile)
    #print(json.dumps(data, sort_keys=True, indent=4))

    # create Running Containers metric
    m = {}
    m['type'] = 'IntCounter'
    m['name'] = metricPath + ":Running Containers"
    m['value']= "{0}".format(len(data))
    metricDict['metrics'].append(m)


    for container in data:
        name = container['Names'][0];
        containerMetricPath = metricPath + '|Containers|' + name
        writeMetrics(container, containerMetricPath, metricDict, containerMap)

        url = "https://{0}:{1}/containers{2}/stats".format(dockerhost, dockerport, name)
        container_data = streamUrl(url, certfile, keyfile)
        #print(json.dumps(container_data, sort_keys=True, indent=4))
        writeMetrics(container_data, containerMetricPath, metricDict, statsMap)


def main(argv):

    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", help = "verbose output",
        dest = "verbose", default = False, action = "store_true")

    parser.add_option("-H", "--hostname", default = "localhost",
        help = "hostname EPAgent is running on", dest = "hostname")
    parser.add_option("-p", "--port", help = "port EPAgent is connected to",
        type = "int", default = 8080, dest = "port")
    parser.add_option("-m", "--metric_path", help = "metric path header for all metrics",
        #dest = "metricPath", default = "Docker|{0}".format(socket.gethostname()))
        dest = "metricPath", default = "Docker")
    parser.add_option("-d", "--docker_host", help = "docker hostname",
        dest = "dockerhost", default = "localhost")
    parser.add_option("-r", "--docker_port", help = "docker Remote API port",
        type = "int", dest = "dockerport", default = "2376")
    parser.add_option("-c", "--certificate", help = "https certificate",
        dest = "certfile", default = "")
    parser.add_option("-k", "--private_key", help = "https private key",
        dest = "keyfile", default = "")

    (options, args) = parser.parse_args();

    if options.verbose == True:
        print("Verbose enabled")

    # Configure URL and header for RESTful submission
    url = "http://{0}:{1}/apm/metricFeed".format(options.hostname,
        options.port)
    headers = {'content-type': 'application/json'}

    if options.verbose:
        print("Submitting to: {0}".format(url))

    submissionCount = 0



    while True:

        start = datetime.now()

        # Metrics are collected in the metricDict dictionary.
        metricDict = {'metrics' : []}

        collectDocker(metricDict, options.metricPath, options.dockerhost, options.dockerport, options.certfile, options.keyfile)

        #
        # convert metric Dictionary into a JSON message via the
        # json package.  Post resulting message to EPAgent RESTful
        # interface.
        #

        try:
            r = requests.post(url, data = json.dumps(metricDict),
                              headers = headers)
        except requests.ConnectionError as err:
            print("Unable to connect to EPAgent via URL \"{}\": {}\ncheck httpServerPort and that EPAgent is running!".format(url, err))
            sys.exit(1)

        if options.verbose:
            print("jsonDump:")
            print(json.dumps(metricDict, indent = 4))

            print("Response:")
            response = json.loads(r.text)
            print(json.dumps(response, indent = 4))

            print("StatusCode: {0}".format(r.status_code))

        submissionCount += 1
        # print("Submitted metric: {0}".format(submissionCount))

        end = datetime.now()
        delta = end-start
        howlong = 15.0 - delta.seconds
        howlong = (howlong * 100000 - delta.microseconds) / 100000
        time.sleep(howlong)

if __name__ == "__main__":
    main(sys.argv)
''
