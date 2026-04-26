Brute Force Attack Detection using Splunk

OVERVIEW

This project shows how I used Splunk to detect brute force login attempts from log data. The goal was to simulate what a SOC analyst would do when monitoring failed logins.

OBJECTIVE

Identify suspicious login activity where multiple failed attempts happen from the same IP address.

TOOLS USED

* Splunk
* Sample CSV log data

DATASET

I created a small dataset with the following fields:

* _time
* EventCode
* Account_Name
* src_ip

EVENT CODE USED:

* 4625 = failed login
* 4624 = successful login

WHAT I DID

* Uploaded the dataset into Splunk
* Searched for failed login attempts (EventCode 4625)
* Counted how many times each user/IP combination appeared
* Filtered results where attempts were greater than 5

SPL QUERY
  Dectection Query:
    index=soc_project EventCode=4625
    | stats count by Account_Name, src_ip
    | where count > 5
    | sort -count
  Investigation Query:
    index=soc_project (Account_Name="john" OR Account_Name="admin")
    | table _time, Account_Name, src_ip, EventCode
    | sort _time
  Login Success Check:
    index=soc_project (EventCode=4625 OR EventCode=4624)
    | stats count by Account_Name, EventCode

RESULTS
I found multiple failed login attempts from the same IPs:

* 192.168.1.10 targeting user “john”
* 10.0.0.5 targeting user “admin”

Both showed more than 5 failed attempts, which is a strong indicator of a brute force attack.

ALERT

I created an alert in Splunk that triggers when this condition is met, so it can be monitored in real time.

SCREENSHOTS
1. Data set upload
  <img width="1512" height="829" alt="Addingdataset" src="https://github.com/user-attachments/assets/da316ac1-e520-40ff-98b4-05efc0c3f7e9" />

2. Data Ingestion
  <img width="1512" height="829" alt="data_ingestion" src="https://github.com/user-attachments/assets/ac2d62ef-c67d-4ce5-93e2-4dd00da7024b" />

3. Detection Results
  <img width="1510" height="614" alt="detection_results" src="https://github.com/user-attachments/assets/0146f599-2185-404f-bb5c-e274f8797fc5" />

4. Investigation Timeline
  <img width="1512" height="805" alt="investigation_timeline" src="https://github.com/user-attachments/assets/a6776828-4518-49a0-a372-372d50508c91" />

5. Dashboard Visualization
  <img width="1512" height="731" alt="Dashboard" src="https://github.com/user-attachments/assets/b5f9a64e-b1b3-440d-90e8-c3d7bbd6bd82" />

6. Alert Configuration
  <img width="1512" height="390" alt="Alert" src="https://github.com/user-attachments/assets/b7afb0aa-4cc6-4c78-b60d-b0c014312b13" />


WHAT I LEARNED

This project helped me understand how to:

* Work with log data in Splunk
* Write basic SPL queries
* Detect simple attack patterns
* Think like a SOC analyst
