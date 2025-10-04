# falcon-exporter
Crowdstrike Falcon Exporter for Prometheus

*Currently only returns the aggregate metrics*

### Docker Command

Quick Start:
```
docker run -p 9122:9122 -e API_USER='example' -e API_PASS='password123' linickx/falcon-exporter
```

Using a config file and your own CA bundle (*useful if behind an SSL intercepting proxy*):
```
docker run -p 9122:9122 -v /home/nick/falcon-exporter/my.falcon.yml:/etc/falcon-exporter/config.yml -v /home/nick/falcon-exporter/my.ca_bundle.pem:/etc/falcon-exporter/ca.pem linickx/falcon-exporter
```

### Environment Variables
The following variables can be set:

* `CONFIG_FILE` = Path to a config file
* `CA_FILE` = Path to a CA (bundle) file
* `API_USER` = API Username
* `API_PASS` = API Password
* `API_FILTER` = A Filter Query, e.g: `"device.machine_domain:'mycompany.local'"`


### prometheus.yml
This assumes that prometheus and falcon-exporter are on the same host, update as necessary.
```
  - job_name: 'falcon'
    scrape_interval: 300s
    static_configs:
        - targets: ['127.0.0.1:9122']
```

### Running without Docker
If you're not using Docker, to run as a local python script you can use a different path for the config.yml and CA bundle; e.g:
```
$ export CONFIG_FILE=my.falcon.yml
$ export CA_FILE=my.ca_bundle.pem
$ ./falcon-exporter.py
[INFO]  * Running on http://0.0.0.0:9122/ (Press CTRL+C to quit)
```