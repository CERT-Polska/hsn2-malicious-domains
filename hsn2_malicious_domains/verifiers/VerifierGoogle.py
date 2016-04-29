# Copyright (c) NASK
#
# This file is part of HoneySpider Network 2.1.
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import urllib2

from hsn2_malicious_domains.verdict.mySingleCheckerVerdict import MySingleCheckerVerdict
from hsn2_malicious_domains.verifiers.VerifierAbstract import VerifierAbstract


class VerifierGoogle(VerifierAbstract):

    def __init__(self):
        pass

    def getBody(self, toCheck):
        result = "%d\n" % len(toCheck)
        for domain in toCheck:
            result = "%s%s\n" % (result, domain)
        return result

    def mapVerdict(self, googleVerdict):
        if googleVerdict == "ok":
            return MySingleCheckerVerdict.BENIGN
        if googleVerdict in ["phishing", "malware", "phishing,malware"]:
            return MySingleCheckerVerdict.MALICIOUS
        return MySingleCheckerVerdict.UNKNOWN

    def verify(self, toCheck, type_, config):
        toCheck = list(toCheck)
        result = dict()
        url = 'https://sb-ssl.google.com/safebrowsing/api/lookup?client=%s&apikey=%s&appver=1.5.2&pver=3.0' % (
            'python', config.get("verifier", "apikey"))

        if type_ == VerifierAbstract.IP:
            for domain in toCheck:
                result[domain] = MySingleCheckerVerdict.UNKNOWN
            return result
        else:
            response = urllib2.urlopen(url, self.getBody(toCheck))
            arr = response.readlines()
            logging.info(arr)
            length = len(arr)
            if length == 0:
                for domain in toCheck:
                    result[domain] = MySingleCheckerVerdict.BENIGN
                return result

            for x in xrange(length):
                result[toCheck[x]] = self.mapVerdict(arr[x].strip())
            return result

    def getName(self):
        return "Google verifier"
