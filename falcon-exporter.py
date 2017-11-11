#!/usr/bin/env python
# coding=utf-8
# Python linter configuration.
# pylint: disable=I0011
# pylint: disable=C0301
# pylint: disable=W0702
# I don't get W0702, I want to catch all exceptions..  so, disabling.
""" Prometheus Crowdstrike Falcon Exporter

    TODO:
    * Don't copy unfinished code from ise-exporter
    * Don't use globals!
    * Test / Travis

"""

import sys
import os
import logging
import datetime
import json
from xml.etree import ElementTree


logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO) # change WARNING to DEBUG if you are a ninja
logger = logging.getLogger("falcon")
version = "0.1"

try:
    import yaml
except:
    logger.error("pyyaml not installed - http://pyyaml.org")
    logger.debug("Exception: %s", sys.exc_info()[0])
    sys.exit(1)

try:
    from flask import Flask, make_response
except:
    logger.error("Flask not installed - http://flask.pocoo.org/")
    logger.debug("Exception: %s", sys.exc_info()[0])
    sys.exit(1)

try:
    import requests
except:
    logger.error("Requests not installed - http://docs.python-requests.org/en/master/")
    logger.debug("Exception: %s", sys.exc_info()[0])
    sys.exit(1)

# Response variables
server = "falcon-exporter/" + version
headers = {
    'Content-Type':'text/plain',
    'Cache-Control':'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0',
    'Last-Modified':datetime.datetime.now(),
    'Pragma':'no-cache',
    'Expires':'-1',
    'Server':server}


def display_error(msg):
    """ Print Error to Console as well as HTTP Response
    """
    global logger
    global version
    global headers
    logger.critical(msg)
    # 503 unailable, i.e. admin needs to fix something
    return make_response(msg, '503', headers)


app = Flask(__name__)
@app.route("/")
def route_root():
    """ Respond to requests :)
    """
    global version
    global headers
    string = '<html><head><title>Crowdstrike Falcon Exporter</title></head>\
<body><h1>Crowdstrike Falcon Exporter for Prometheus v{}</h1><p><a href="/metrics">Metrics</a></p></body>\
</html>'.format(version)
    return string

@app.route("/metrics")
def route_metrics():
    """ print metrics
    """
    global logger
    global server
    global version
    global headers

    yfile = os.getenv('CONFIG_FILE', "/etc/falcon-exporter/config.yml")
    cafile = os.getenv('CA_FILE',"/etc/falcon-exporter/ca.pem")

    if os.path.isfile(cafile):
        r_ssl_verify = cafile
        logger.info("Using " + cafile + " for SSL verification")
    else:
        logger.warning("Cannot find file: " + cafile + " SSL verification will be disabled")
        r_ssl_verify = False

    if os.path.isfile(yfile):
        try:
            datastream = open(yfile, 'r') # Open the yaml file
            csyaml = yaml.load(datastream)
        except:
            return display_error("Failed to load Yaml! | Exception: " + str(sys.exc_info()[1]))

        # Check to see if the YAML has eveything we need?
        yaml_vars = ['apiuser', 'apipass']
        for expected_var in yaml_vars:
            try:
                csyaml[expected_var]
            except:
                return display_error("Variable " + expected_var + " not set in " + yfile)

        logger.info("Using " + yfile + " for Credentials")
        # Set the vars, we know we have them.
        apiuser = csyaml['apiuser']
        apipass = csyaml['apipass']

        # Allow Adding a Filter
        try:
            apifilter = str(csyaml['apifilter'])
        except:
            apifilter = ''
    else:
        apiuser = os.getenv('API_USER', "crowdstrike")
        apipass = os.getenv('API_PASS', "falcon")
        apifilter = os.getenv('API_FILTER', "")

    """
        API Request
    """

    # Crowdstrike Falcon - The Query.
    ranges = [{"From": 0, "To": 20}, {"From": 20, "To": 40}, {"From": 40, "To": 60}, {"From": 60, "To": 80}, {"From": 80, "To": 100}]
    falcon_data = {"name": "myagg", "type": "range", "field": "max_severity", "filter": apifilter, "ranges":ranges}
    falcon_data_as_array = [falcon_data] # Save as Array for Submission
    apiurl = 'https://falconapi.crowdstrike.com/detects/aggregates/detects/GET/v1'

    # Curl Request Headers
    request_headers = {}
    request_headers['user-agent'] = server + " (https://github.com/linickx/falcon-exporter)"
    request_headers['Content-Type'] = "application/json"

    # Make the Request!
    try:
        r = requests.post(apiurl, verify=r_ssl_verify, auth=(apiuser, apipass), headers=request_headers, data=json.dumps(falcon_data_as_array))
    except:
        return display_error("Exception: " + str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]))

    response = r.json() # Save the response

    # Check response for errors
    try:
        if response['errors'][0]['code'] == 401:
            return display_error("Authentication Failed - " + str(response['errors'][0]['code']) + " " + response['errors'][0]['message'])
        elif response['errors'][0]['code'] == 403:
            return display_error("Incorrect API URL - " + str(response['errors'][0]['code']) + " " + response['errors'][0]['message'])
        else:
            return display_error("Undefined API Error - " + str(response['errors'][0]['code']) + " " + response['errors'][0]['message'])
    # This Except means all is ok.
    except IndexError:
        logger.info("API Request Completed | Traceid %s", response['meta']['trace_id'])

    #pprint.pprint(response['resources'][0]['buckets'])

    # Setup a dict to save metrics
    metrics = {}

    # Get what we need and save.
    for water in response['resources'][0]['buckets']:
        if water['label'] == '0.0-20.0':
            metrics['sev_Infomational'] = water['count']
        elif water['label'] == '20.0-40.0':
            metrics['sev_Low'] = water['count']
        elif water['label'] == '40.0-60.0':
            metrics['sev_Medium'] = water['count']
        elif water['label'] == '60.0-80.0':
            metrics['sev_High'] = water['count']
        elif water['label'] == '80.0-100.0':
            metrics['sev_Critical'] = water['count']
        else:
            logger.error("Ignoring unknown label - %s", water['label'])

    #pprint.pprint(metrics)


    prometheus_string = ""

    # build the text string (response)
    for key, value in metrics.items():
        prometheus_metric = "crowdstrike_falcon_" + key
        prometheus_string = prometheus_string + "# TYPE " + prometheus_metric + " counter" + "\n"
        prometheus_string = prometheus_string + prometheus_metric + " " + str(value) + "\n"

    return make_response(prometheus_string, '200', headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port="9122", debug=False)
