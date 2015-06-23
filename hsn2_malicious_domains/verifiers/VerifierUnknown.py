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


class VerifierUnknown(VerifierAbstract):

    def __init__(self):
        pass

    def verify(self, toCheck, type_, config):
        result = dict()
        for domain in toCheck:
            result[domain] = MySingleCheckerVerdict.UNKNOWN
        return result

    def getName(self):
        return "Unknown verifier"
