# auth-log-analyzer
Python tool to parse authentication logs and detect brute-force patterns, built for learning security fundamentals



## V1 Log analysis

I created a sample auth.log file and used regex to parse each line, extracting the hour, access result (Failed/Accepted), username and IP.

I store the results in two separate dictionaries (one for failed attempts, one for successful accesses), grouped by IP, so I can later cross-reference them — e.g. an IP with many failed attempts followed by a successful login is a stronger signal than failed attempts alone.