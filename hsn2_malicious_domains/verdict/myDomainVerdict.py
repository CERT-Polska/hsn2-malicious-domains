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


class MyDomainVerdict():

    def __init__(self, domain):
        self.checked_domain = domain
        self.singleCheckerVerdict = []

    def addSingleVerdict(self, mySingleCheckerVerdict):
        self.singleCheckerVerdict.append(mySingleCheckerVerdict)

    def getSingleVerdicts(self):
        return self.singleCheckerVerdict

    def getCheckedDomain(self):
        return self.checked_domain
