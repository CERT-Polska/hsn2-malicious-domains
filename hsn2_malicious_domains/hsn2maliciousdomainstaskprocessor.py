#!/usr/bin/python -tt

# Copyright (c) NASK
#
# This file is part of HoneySpider Network 2.0.
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
import re

from hsn2_malicious_domains.config import Config
from hsn2_malicious_domains.verdict.myDomainVerdict import MyDomainVerdict
from hsn2_malicious_domains.verdict.mySingleCheckerVerdict import MySingleCheckerVerdict
from hsn2_malicious_domains.verifiers.VerifierAbstract import VerifierAbstract
from hsn2_malicious_domains.verifiers.VerifierFactory import VerifierFactory
from hsn2_commons import hsn2objectwrapper as ow
from hsn2_commons.hsn2osadapter import ObjectStoreException
from hsn2_commons.hsn2taskprocessor import HSN2TaskProcessor
from hsn2_commons.hsn2taskprocessor import ParamException


class MaliciousDomainsTaskProcessor(HSN2TaskProcessor):
    parser = None
    ipRegex = re.compile(
        "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", re.I)
    ipVerifiers = None
    domainVerifiers = None

    def __init__(self, connector, datastore, serviceName, serviceQueue, objectStoreQueue, **extra):
        self.ipVerifiers = []
        self.domainVerifiers = []
        HSN2TaskProcessor.__init__(self, connector, datastore, serviceName, serviceQueue, objectStoreQueue, **extra)

    def getIpList(self):
        ipMessagePath = self.dsAdapter.saveTmp(
            self.currentTask.job, self.objects[0].pcap_ip.getKey())
        f = open(ipMessagePath, 'r')
        return ow.fromIpAddressList(f)

    def getDnsList(self):
        dnsMessagePath = self.dsAdapter.saveTmp(
            self.currentTask.job, self.objects[0].pcap_dns.getKey())
        f = open(dnsMessagePath, 'r')
        return ow.fromDnsList(f)

    def taskProcess(self):
        logging.debug(self.__class__)
        logging.debug(self.currentTask)
        logging.debug(self.objects)

        result = dict()

        if len(self.objects) == 0:
            raise ObjectStoreException(
                "Task processing didn't find task object.")

        if not self.objects[0].isSet("pcap_ip"):
            raise ParamException("pcap_ip param is missing.")

        if not self.objects[0].isSet("pcap_dns"):
            raise ParamException("pcap_dns param is missing.")

        ipList = self.getIpList()
        dnsList = self.getDnsList()

        domains = set()

        for frame in dnsList:
            domain = frame.split()[-1]
            if re.match(self.ipRegex, domain) is not None:
                continue
            domains.add(domain)

        config = Config().getConfig()

        domainVerifiersString = config.get("verifier", "domain")
        ipVerifiersString = config.get("verifier", "ip")

        factory = VerifierFactory()

        self.ipVerifiers = factory.createVerifierList(ipVerifiersString)
        self.domainVerifiers = factory.createVerifierList(
            domainVerifiersString)

        '''
        resultDict should be in format
        {"ip" -> "verdict"}
        '''

        logging.info(self.ipVerifiers)
        logging.info(self.domainVerifiers)

        for verifier in self.ipVerifiers:
            resultDict = verifier.verify(ipList, VerifierAbstract.IP, config)
            for key in resultDict:
                if key not in result:
                    result[key] = MyDomainVerdict(key)
                result[key].addSingleVerdict(
                    MySingleCheckerVerdict(verifier.getName(), resultDict[key]))

        for verifier in self.domainVerifiers:
            resultDict = verifier.verify(
                domains, VerifierAbstract.DOMAIN, config)
            for key in resultDict.keys():
                if key not in result:
                    result[key] = MyDomainVerdict(key)
                result[key].addSingleVerdict(
                    MySingleCheckerVerdict(verifier.getName(), resultDict[key]))

        objectDomainVerdicts = ow.toObjectDomainVerdicts(result)
        self.objects[0].addBytes("malicious_domains_verdict", self.dsAdapter.putBytes(
            bytes(objectDomainVerdicts.SerializeToString()), self.currentTask.job))
        return []

if __name__ == '__main__':
    MaliciousDomainsTaskProcessor()
