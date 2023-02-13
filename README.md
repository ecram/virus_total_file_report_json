# virus_total_file_report_json
System for sending directories samples to VirusTotal and get json's and csv's files with multi-keys, with delimitation of sending files and a timer to avoid blocking.

The program does the following:
1. Toggle Virus Total keys to get more speed.
2. Gets hash SHA256 of the files directories and puts them in the execution queue.
3. Obtains the JSON report 'data' from VirusTotal and checks if there are any errors.
4. Save the JSON file.
5. Extracts the most relevant information from 'data' and stores it in a file called 'executables_samples.csv'.
6. Generates a command line log with information about the samples.
7. Allows delimiting the number of samples sent to Virus Total and timer to avoid blocking.

Enjoy it.
