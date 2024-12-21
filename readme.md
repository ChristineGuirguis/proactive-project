Proactive Threat Detection and Analysis
Table of Contents
1.	Introduction
2.	Project Overview
3.	Environment Setup
4.	Tools and Techniques
5.	Implementation Steps 
o	1. Malware Simulation
o	2. Network Monitoring with Suricata
o	3. Log Analysis with Splunk
o	4. Memory Analysis with Volatility
o	5. Malware Detection with YARA
6.	Findings
7.	How to Use
8.	Team
________________________________________
Introduction
This project focuses on detecting and analyzing the Zeus Banking Trojan using proactive security methodologies. We leveraged tools like Suricata, Splunk, Volatility, and YARA in a simulated malware environment.
________________________________________
Project Overview
•	Goal: Build a robust threat detection and analysis system for the Zeus Trojan.
•	Techniques: Network monitoring, memory analysis, and signature-based detection.
•	Deliverables: GitHub repository with configurations and code, a walkthrough video, and detailed documentation.
________________________________________
Environment Setup
1.	Virtual Machines: 
o	A Windows VM (infected system) to simulate malware execution.
o	A Linux VM (Kali) for monitoring and analysis.
2.	Communication: Ensure VMs can ping each other (same network).
________________________________________
Tools and Techniques
•	Suricata: Network intrusion detection and prevention.
•	Splunk: Centralized log analysis and correlation.
•	Volatility: Memory forensics and malware analysis.
•	YARA: Signature-based malware detection.
•	Zeus Malware: Retrieved from theZoo repository.
________________________________________
Implementation Steps
1. Malware Simulation
•	Set up a Windows VM.
•	Download Zeus Trojan from theZoo repository.
•	Execute the malware in a controlled environment.
2. Network Monitoring with Suricata
1.	Install Suricata (was already istalled) and update it:
On the Linux VM: 
 
2.	Start Monitoring: 
 
3.	Analyze Logs:
Check alerts in fast.log: 
 
 
3. Log Analysis with Splunk
1.	Install Splunk:
On the Windows VM, download and install Splunk.
2.	Configure Log Monitoring:
Set up Splunk to monitor system, application, and security logs.
3.	Correlation and Dashboards: 
o	Create rules to link network and system anomalies.
o	Build visual dashboards to display malicious activity.
4. Memory Analysis with Volatility
1.	Capture Memory Dump:
Use a tool like DumpIt to extract memory from the Windows VM.
2.	Analyze with Volatility: 
o	List processes: 
o	Identify malicious code: 
o	Dump injected regions for analysis: 
5. Malware Detection with YARA
1.	Write YARA Rules
2.	Scan with YARA
________________________________________
Findings
•	Zeus exhibits suspicious behaviors, such as: 
o	Abnormal network traffic (e.g., C2 communication).
o	Injected code in processes.
o	Use of suspicious Windows APIs like RegisterDragDrop.
•	Memory regions contained malicious artifacts (e.g., NOP sleds, MZ headers).
________________________________________
How to Use
1.	Clone the repository. 
2.	https://github.com/ChristineGuirguis/proactive-project.git
3.	Follow the environment setup instructions.
4.	Execute the tools in the order described in the walkthrough.
5.	Review outputs and logs for Zeus-related indicators.
________________________________________
Team
•	Mohammed Ayman
•	Ahmed Sameh
•	Mina Nader
•	Christine Guirguis

