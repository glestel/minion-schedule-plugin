# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = []

setup(name="minion-schedule-plugin",
      version="0.0",
      description="Schedule Manager Plugin for Minion",
      url="",
      author="",
      author_email="",
      packages=['minion', 'minion.plugins', 'minion.plugins.schedule_manager'],
      namespace_packages=['minion', 'minion.plugins'],
      include_package_data=True,
      install_requires=install_requires)
