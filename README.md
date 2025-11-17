# active_services
I prepared a script in PowerShell to protect against malware registering as a system service. Scope of script operation:

-Monitoring the list of active and installed services in the system.

-Detection of newly added, suspicious services.

-Executable file path analysis and digital signature verification.

-Automatically stopping and disabling a suspicious service.

-Generating a CSV report with audit results.
