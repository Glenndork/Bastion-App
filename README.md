# Bastion

A Desktop-based Malware Detection Application using Support Vector Machines

- Features
1. Malware Scanning -this feature allows users to set a directory for
malware scanning. This process leverages the trained model. When a
directory is set, the application scans the previous files found in the
directory. When a new file is detected, the application scans it, extracts its
features, and feeds it to the trained model. Then, the trained model predicts
if it is malware or not.

2. SMS Notification - – the researchers integrate Vonage Api; this API sends an SMS
alert when malware is detected.

3. Scan History – the researchers implemented a history of all the files
scanned by the application. A button can be clicked to access the log.
## Developers

Karl Francis S. Catolico
Glenn B. Viola
