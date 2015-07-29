# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import json
import requests
import time
import minion.curly
from minion.plugins.base import BlockingPlugin


class SchedulePlugin(BlockingPlugin):
    PLUGIN_NAME = "Schedule Manager"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "heavy"

    API_PATH = "http://127.0.0.1:8383"

    SCAN_ERROR = {
        "Summary": "Could not launch scan",
        "Description": "The worker was not able to launch the scan",
        "URLs": [ {"URL": None, "Extra": None}],
    }

    def do_run(self):
        # Get the array of plans to run
        if "plans" in self.configuration:
            plans = self.configuration.get('plans')

        # Get the name of the group to run (mandatory)
        if "group" in self.configuration:
            group = self.configuration.get('group')
        else:
            raise Exception('No group is specified for the scheduled run')

        # Get the email for scan configuration
        if "email" in self.configuration:
            email = self.configuration.get('email')
        else:
            email = "schedule@minion.org"

        # Retrieve every target for the group
        r = requests.get(self.API_PATH + "/groups" + group)
        r.raise_for_status()
        targets = r.json()['sites']

        # Build the scan list
        scan_list = []
        for target in targets:
            # Get plans associated to the target
            r = requests.get(self.API_PATH + "/site?url=" + target)
            r.raise_for_status()
            target_plans = r.json()['sites'][0]["plans"]

            # Browse every plan of a target
            for target_plan in target_plans:
                # Check if the plan is wanted
                if target_plan in plans:
                    scan_list.append({"target": target, "plan": target_plan})

                # Add it anyway if no plan is specified
                elif not plans:
                    scan_list.append({"target": target, "plan": target_plan})

        # Browse the list of jobs to do
        for job in scan_list:
            scan = self.launch_scan(email, job["plan"], job["target"])

            # Check the scan has been well started
            if not scan["success"]:
                issue = self.SCAN_ERROR.copy()
                issue["Summary"] += " " + scan["reason"]
                issue["URLs"] = [{"URL": job["target"]}]

                self.report_issue([issue])

            # Wait till the scan is finished
            # TODO FIXME use deferred thread
            while True:
                time.sleep(5)

                # Get the scan status
                r = requests.get(self.API_PATH + "/scans/" + scan["id"] + "/summary")
                r.raise_for_status()
                status = r.json()["summary"]["state"]

                # Check if the scan is finished
                if status == "FINISHED":
                    break

                # Check if something went wrong
                if status in ["STOPPED", "FAILED"]:
                    # TODO FIXME the summary of a scan doesn't contain reason if failure
                    break

            # TODO Update progress

        self.report_progress(42, "Ok")

    def launch_scan(self, email, plan, target):
        """ Scan the given target with the given plan

        Create and launch a scan on the given target with the given plan

        Parameters
        ----------
        email : string
            Email address of the user who want to scan the target
        plan : string
            Name of the plan to use
        target : string
            Url of the website to scan

        Returns
        -------
        array
            Success
            reason if no success of the scan
             id of the scan

        """

        # Create the scan
        req = requests.post(self.API_PATH + "/scans",
                            headers={'Content-Type': 'application/json'},
                            data=json.dumps({
                                'user': email,
                                'plan': plan,
                                'configuration': {'target': target}}))
        req.raise_for_status()
        j_scan = req.json()['scan']

        # Start the scan
        req = requests.put(self.API_PATH + "/scans/" + j_scan['id'] + "/control",
                           headers={'Content-Type': 'text/plain'},
                           data="START",
                           params={'email': email})
        req.raise_for_status()

        result = req.json()
        success = result['success']
        reason = result.get('error') if 'error' in result else '-'
        scan_id = j_scan['id']
        return {"success": success, "reason": reason, "id": scan_id}

