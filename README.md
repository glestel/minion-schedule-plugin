Minion Schedule Plugin
===================

This is a plugin for Minion that allows to run selected plans of a given group.

Installation
------------

You can install the plugin by running the following command in the minion-schedule-plugin repository (with the virtual environment activated if needed):

```python setup.py develop```

Example of plan
---------------

```
[
  {
    "configuration": {
      "report_dir": "/tmp/artifacts/",
      "group": "test",
      "plans": [
        "test plan"
      ],
      "parallel_task": 2,
      "only_functional": true,
      "email": "schedule@minion.com"
    },
    "description": "The schedule plugin will run a scan for every target of a group with plan restriction.",
    "plugin_name": "minion.plugins.schedule_manager.SchedulePlugin"
  }
]
```
Available configuration option
------------------------------
Most of the options are not mandatory and have default values.
* ```report_dir``` : directory where output and reports will be saved. By default, the path used is `/tmp/artifacts`
* ```group ``` : name of the group in Minion that will be used for running the scan campaign. This option is mandatory
* ```plans ``` : array containing name of plans to run. 
* ```parallel_task ``` : number of scan to run simultaneously. Default value is `1` (single thread) 
* ```only_functional ``` : run scan only if the previous scan ended in a `FINISHED` state or was never launched. Default value is `False`
* ```email ``` : email of the account that will be used for launching scans. This option is mandatory and the email need to be valid.

