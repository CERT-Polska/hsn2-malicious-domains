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

from hsn2_malicious_domains.verdict.mySingleCheckerVerdict import MySingleCheckerVerdict
from hsn2_malicious_domains.verifiers.VerifierAbstract import VerifierAbstract
from config import Config


class VerifierStatic(VerifierAbstract):
    maliciousList = list()

    def __init__(self):
        f = open(Config().getConfig().get("verifier", "malicious_list"), 'r')
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line != "":
                self.maliciousList.append(line)

    def verify(self, toCheck, type_, config):
        result = dict()
        for domain in toCheck:
            if domain in self.maliciousList:
                result[domain] = MySingleCheckerVerdict.MALICIOUS
            else:
                result[domain] = MySingleCheckerVerdict.BENIGN
        return result

    def getName(self):
        return "Static verifier"
