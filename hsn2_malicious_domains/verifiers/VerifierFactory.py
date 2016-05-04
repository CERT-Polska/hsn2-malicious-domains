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

import ConfigParser

from hsn2_malicious_domains.verifiers.VerifierGoogle import VerifierGoogle
from hsn2_malicious_domains.verifiers.VerifierStatic import VerifierStatic
from hsn2_malicious_domains.verifiers.VerifierUnknown import VerifierUnknown


class VerifierFactory(object):

    verifiersLists = None

    def __init__(self):
        self.verifiersLists = {}

    def getVerifier(self, name):
        if name == "unknown":
            return VerifierUnknown()
        if name == "google":
            return VerifierGoogle()
        if name == "static":
            return VerifierStatic()

    def createVerifierList(self, configValue):
        arr = configValue.split(",")
        tmpDict = []
        for verifier in arr:
            verifierObj = self.getVerifier(verifier)
            if verifierObj is not None:
                tmpDict.append(verifierObj)

        if len(tmpDict) == 0:
            tmpDict.append(self.getVerifier("unknown"))
        return tmpDict

    def getVerifierList(self, type_, config):
        try:
            return self.verifiersLists[type_]
        except KeyError:
            try:
                configValue = config.get("verifier", type_)
                self.verifiersLists[type_] = self.createVerifierList(configValue)
                return self.verifiersLists[type_]
            except ConfigParser.NoOptionError:
                return self.getVerifierList("default", config)
