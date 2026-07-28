# auth-log-analyzer
Python tool to parse authentication logs and detect brute-force patterns, built for learning security fundamentals



## V1 Log analysis

I created a sample auth.log file and used regex to parse each line, extracting the hour, access result (Failed/Accepted), username and IP.

I store the results in two separate dictionaries (one for failed attempts, one for successful accesses), grouped by IP, so I can later cross-reference them — e.g. an IP with many failed attempts followed by a successful login is a stronger signal than failed attempts alone.

## V2 Brute force detection

Now, we check the IP and the logs attempts and its diference in time. If the attacker tried to log in 5 times in 60 seconds we receive an alert.

To log the time (since it used to be stored as string) I used datetime, so I can properly check the time.

After detecting a brute force attack, we compare the ip with the successful log dictionary (accesos_por_ip), if the IP is logged, a severe warning is shown since the brute force attack actually worked.


## V3 JSON creation

Now I changed the output format, creating a new directory called "reports" that stores the reports made based on the file given by parameters.

I check ip, severity, failed attempts, seconds, users tried, if the access was successful, access user and access hour and attach it to the JSON file with its date to better recognition.

To get the command line argument I use 'sys.argv' to receive the file to analyze.