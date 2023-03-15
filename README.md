# CVE-2023-23397_EXPLOIT_0DAY
Exploit for the CVE-2023-23397
Credit to domchell

EML/MSG Checker for the exploit: 

    #!/usr/bin/env python3
    
    from extract_msg import AppointmentMeeting
    from ..helpers import Status
    from ..task import Task
    from ..report import Report
    from .base import BaseWorker
    class OutlookMSG(BaseWorker):
    def analyse(self, task: Task, report: Report, manual_trigger: bool=False):
    print(task.file.msg_data)
    if not task.file.msg_data or not isinstance(task.file.msg_data, AppointmentMeeting):
    report.status = Status.NOTAPPLICABLE
    return
    self.logger.debug(f'analysing AppontmentMeeting in {task.file.path}...')
    if task.file.msg_data.reminderFileParameter is not None:
    report.status = Status.ALERT
    # suspicious for cve-2023-23397: https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/
    report.add_details('CVE-2023-23397', f'A parameter used to exploit this vulnerability is present in the mail: "{task.file.msg_data.reminderFileParameter}"')

[Based on Pandora Framework](https://github.com/pandora-analysis/pandora/blob/0dd6b01956b0501c28e4a7c1128298dcd6a499b8/pandora/workers/outlookmsg.py)

