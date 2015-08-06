# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import json
import Queue
import requests
import time
import uuid
from minion.plugins.base import BlockingPlugin, AbstractPlugin
from threading import Thread, RLock


class SchedulePlugin(BlockingPlugin):
    PLUGIN_NAME = "Schedule Manager"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "heavy"

    API_PATH = "http://127.0.0.1:8383"

    SCAN_ERROR = {
        "Summary": "Could not launch scan",
        "Description": "The worker was not able to launch the scan",
        "URLs": [{"URL": None, "Extra": None}],
        }

    alt_configuration = {
        "report_dir": "/tmp/artifacts/",
        "group": "test",
        "plans": [
            "Nmap"
        ],
        "email": "guillaume.lestel@gmail.com",
        "only_functional": True,
        "parallel_task": 2
    }

    # Instantiation of output
    output_id = str(uuid.uuid4())
    schedule_stdout = ""
    schedule_stderr = ""

    report_dir = "/tmp/"

    # Utils for multi threading
    scan_queue = Queue.Queue(maxsize=0)
    process_list = []
    counter = 0
    task_number = 0

    counter_lock = RLock()
    output_lock = RLock()

    # plans planned for scanning
    plans = []

    # Flag for scanning only - and FINISHED targets
    only_functional = False

    def do_run(self):
        # Used for debug
        if not self.configuration:
            self.configuration = self.alt_configuration

        # Get the path to save output
        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']

        # Get the array of plans to run
        if "plans" in self.configuration:
            self.plans = self.configuration.get('plans')

        # Get the name of the group to run (mandatory)
        if "group" in self.configuration:
            group = self.configuration.get('group')
        else:
            self.schedule_stderr += "No group is specified for the scheduled run\n"
            raise Exception('No group is specified for the scheduled run')

        # Get the email for scan configuration
        if "email" in self.configuration:
            email = self.configuration.get('email')
        else:
            email = "schedule@minion.org"

        # Set the number of scan to run in parallel
        if "parallel_task" in self.configuration:
            num_worker = self.configuration["parallel_task"]
        else:
            num_worker = 1

        # Set flag for scanning only - or FINISHED target
        if "only_functional" in self.configuration:
            self.only_functional = self.configuration.get("only_functional")

        # Retrieve every target for the group
        try:
            r = requests.get(self.API_PATH + "/groups/" + group)
            r.raise_for_status()
        except Exception as e:
            self.schedule_stderr += e.message
            self._save_artifacts()

            failure = {
                "hostname": "Utils plugins",
                "exception": self.schedule_stderr,
                "message": "Plugin failed"
            }
            self._finish_with_failure(failure)

        # Check the request is successful
        success = r.json()["success"]
        if not success:
            raise Exception("Could not retrieve info about group " + group + " because " + r.json()["reason"])

        targets = r.json()["group"]['sites']

        # Build the scan list
        for target in targets:
            # Sleep to not DOS the API
            time.sleep(1)
            # Get plans associated to the target
            r = requests.get(self.API_PATH + "/sites?url=" + target)

            # FIXME sometimes the API responds with blank answer
            try:
                r.raise_for_status()
                target_plans = r.json()['sites'][0]["plans"]
                target_id = r.json()['sites'][0]["id"]
            except Exception as e:
                self.schedule_stderr += e.message + "\n"
                continue

            # Browse every plan of a target
            for target_plan in target_plans:
                # Add plan to the list if needed
                self.check_plan(target, target_plan, target_id)

        # Sort the scans to schedule into a prioritized order
        self.sort_scans()

        # Create workers to launch scans
        for i in range(num_worker):
            worker = Thread(target=self.scan_worker, args=(email,))
            worker.setDaemon(True)
            worker.start()

        # Wait for the end of all scan
        self.scan_queue.join()

        # Save result
        self.schedule_stdout += "Scanning over, scanned " + str(self.task_number) + " targets\n"
        self._save_artifacts()

        self._finish_with_success(AbstractPlugin.EXIT_STATE_FINISHED)

    # Function used to add the target with its plan to the scan_queue
    # Will add scan regarding configuration set during initialization
    # Params:
    #   target : url to scan
    #   target_plan : plan to apply
    #   target_id : id of the url in minion
    def check_plan(self, target, target_plan, target_id):
        # Check if the plan is wanted the expected plans are defined
        if target_plan not in self.plans and self.plans:
            return

        # Get the status of the last scan
        params = {'site_id': target_id, 'plan_name': target_plan, 'limit': 1}
        r = requests.get(self.API_PATH + "/scans", params=params)

        try:
            r.raise_for_status()
        except Exception as e:
            self.schedule_stderr += e.message + "\n"
            return

        j = r.json()

        # Check the request has results
        if not j.get('success'):
            msg = str("Can't get the last scan for the site %s and plan %s, reason : %s" %
                      (target, target_plan, j.get('reason')))
            self.schedule_stderr += msg + "\n"

            return

        # Get info about last scan
        last_scan = j.get("scans")

        # Set default value if the scan has never been started
        if not last_scan:
            started_date = 0
            state = "-"
        else:
            started_date = last_scan[0]["created"]
            state = last_scan[0]["state"]

        # Check if the last scan must have well finished
        if self.only_functional and state not in ["FINISHED", "-"]:
            return

        # Add info to the process list
        self.process_list.append({"target": target, "plan": target_plan, "started": started_date, "state": state})
        self.task_number += 1

    # Function used to sort the scans planned and order them into the scanning queue
    def sort_scans(self):
        # Order from ascending start date (never started scan will be in first)
        self.process_list.sort(key=lambda scan_job: scan_job["started"])

        # Import result into the queue
        for job in self.process_list:
            self.scan_queue.put(job)

    def scan_worker(self, email):
        while True:
            # Retrieve item to scan
            job = self.scan_queue.get()

            # Launch the scan
            scan = self.launch_scan(email, job["plan"], job["target"])

            # Check the scan has been well started
            if not scan["success"]:
                issue = self.SCAN_ERROR.copy()
                issue["Summary"] += " " + scan["reason"]
                issue["URLs"] = [{"URL": job["target"]}]

                # Report the finished job
                self.report_issue(issue)

                # Update progress
                self.counter_lock.acquire()
                self.counter += 1
                self.counter_lock.release()

                # Update thread synchronization
                self.scan_queue.task_done()

                continue

            # Wait till the scan is finished
            while True:
                time.sleep(10)

                # Get the scan status
                r = requests.get(self.API_PATH + "/scans/" + scan["id"] + "/summary")
                r.raise_for_status()
                status = r.json()["summary"]["state"]

                # Check if the scan is finished
                if status == "FINISHED":
                    break

                # Check if something went wrong
                if status in ["STOPPED", "FAILED", "ABORTED"]:
                    self.output_lock.acquire()
                    self.schedule_stderr += "The scan " + job["plan"] + " on " + job["target"] + \
                                            " did not success and exited with the status " + status + "\n"
                    self.output_lock.release()

                    self.scan_queue.task_done()
                    # TODO FIXME the summary of a scan doesn't contain reason if failure
                    break

            # Update progress
            self.counter_lock.acquire()
            self.counter += 1
            output = "Scanned " + job["target"] + " with " + job["plan"]
            self.report_progress(self.counter/self.task_number, output)
            self.counter_lock.release()

            self.output_lock.acquire()
            self.schedule_stdout += output + "\n"
            self.output_lock.release()

            # Update thread synchronization
            self.scan_queue.task_done()

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

    # Function used to save output of the plugin
    def _save_artifacts(self):
        stdout_log = self.report_dir + "STDOUT_" + self.output_id + ".txt"
        stderr_log = self.report_dir + "STDERR_" + self.output_id + ".txt"
        output_artifacts = []

        if self.schedule_stdout:
            with open(stdout_log, 'w+') as f:
                f.write(self.schedule_stdout)
            output_artifacts.append(stdout_log)
        if self.schedule_stderr:
            with open(stderr_log, 'w+') as f:
                f.write(self.schedule_stderr)
            output_artifacts.append(stderr_log)

        if output_artifacts:
            self.report_artifacts("Schedule Output", output_artifacts)


# used for debug purpose
if __name__ == "__main__":
    sd = SchedulePlugin()

    sd.do_run()