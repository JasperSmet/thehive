#!/usr/bin/env python
# encoding: utf-8

import sys
import os
import time
import hashlib
import requests
import json
import urlparse
import shutil

from cortexutils.analyzer import Analyzer

class IRMA(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.url = self.getParam(
            'config.url', None, 'IRMA URL parameter is missing')
        self.timeout = self.getParam(
            'config.timeout', 60)
        self.scan = self.getParam(
            'config.scan', 1)
        self.force = self.getParam(
            'config.force', 1)
        self.verify = self.getParam(
            'config.force', False)
        self.filename = self.getParam(
        	'attachment.name', 'noname.ext')
        self.filepath = self.getParam(
        	'file', None, 'File is missing')
        self.hashes = self.getParam(
        	'attachment.hashes', None)
        self.time_start = time.time()

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Irma"
        predicate = "Score"
        value = "\"0\""

        result = {
            "has_result": True
        }

        if(raw["status"] != 1):
            result["has_result"] = False

        if self.service == "scan":

            if "probe_results" in raw:
                result["probe_results"] = raw["probe_results"]

                positives = 0
                totalScans = 0

                for probe in result["probe_results"] :
                    if probe["type"] == "antivirus":

                        ++totalScans
                        
                        if probe["results"]:
                            ++positives
                
                value = "\"{}/{}\"".format(positives, totalScans)

                if positives == 0:
                    level = "safe"
                elif positives < 5:
                    level = "suspicious"
                else:
                    level = "malicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies":taxonomies}

    """Gets antivirus signatures from IRMA for various results.
       Currently obtains IRMA results for the target sample.
       """
    # IRMA statuses https://github.com/quarkslab/irma-cli/blob/master/irma/apiclient.py
    IRMA_FINISHED_STATUS = 50

    def _request_json(self, url, **kwargs):
        """Wrapper around doing a request and parsing its JSON output."""
        try:
            r = requests.get(url, timeout=self.timeout, verify=self.verify, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            self.unexpectedError(e)

    def _post_json(self, url, **kwargs):
        """Wrapper around doing a post and parsing its JSON output."""
        try:
            r = requests.post(url, timeout=self.timeout, verify=self.verify, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            self.unexpectedError(e)

    def _scan_file(self, force):
        # Initialize scan in IRMA.
        init = self._post_json(urlparse.urljoin(self.url, "/api/v1.1/scans"))

        # Post file for scanning.

        IrmaFileName = os.path.join(os.path.dirname(self.filepath),self.filename)

        #make named copy for irma archive
        shutil.copy(self.filepath,IrmaFileName)

        files = {
            "files": open(IrmaFileName, "rb"),
        }
        url = urlparse.urljoin(
            self.url, "/api/v1.1/scans/%s/files" % init.get("id")
        )
        self._post_json(url, files=files, )

        # launch posted file scan
        params = {
            "force": force,
        }
        url = urlparse.urljoin(
            self.url, "/api/v1.1/scans/%s/launch" % init.get("id")
        )
        requests.post(url, json=params, verify=self.verify)

        result = None

        while result is None or result.get(
                "status") != self.IRMA_FINISHED_STATUS or time.time() < self.time_start + self.timeout:
            url = urlparse.urljoin(
                self.url, "/api/v1.1/scans/%s" % init.get("id")
            )
            result = self._request_json(url)
            time.sleep(10)

        return result

    def _get_results(self, sha256):
        # Fetch list of scan IDs.
        results = self._request_json(
            urlparse.urljoin(self.url, "/api/v1.1/files/%s" % sha256)
        )

        if not results.get("items"):
            return

        result_id = results["items"][-1]["result_id"]
        return self._request_json(
            urlparse.urljoin(self.url, "/api/v1.1/results/%s" % result_id)
        )


    def run(self):
        Analyzer.run(self)

        if self.service == 'scan':
            if self.data_type == 'file':
                if self.hashes is None:
                    hash = hashlib.sha256(open(self.filepath, 'r').read()).hexdigest()
                else:
                    # find SHA256 hash
                    hash = next(h for h in self.hashes if len(h) == 64)

                results = self._get_results(hash)

                if not self.force and not self.scan and not results:
                    return {}
                elif self.force or (not results and self.scan):
                    rs = self._scan_file(self.force)
                    hsh = rs["results"][-1]["file_sha256"]
                    results = self._get_results(hsh) or {}

                self.report(results)

            else:
                self.error('Invalid data type')
        else:
            self.error('Invalid service')


if __name__ == '__main__':
    IRMA().run()
