# SSH Auth Logger

A low/zero interaction ssh authentication logging honeypot. Initially developed by [JustinAzoff](https://github.com/JustinAzoff).

[![Dev Build](https://github.com/GAS85/ssh-auth-logger/actions/workflows/docker-dev.yml/badge.svg?branch=dev)](https://github.com/GAS85/ssh-auth-logger/actions/workflows/docker-dev.yml)
[![Test Automation](https://github.com/GAS85/ssh-auth-logger/actions/workflows/go-test.yml/badge.svg)](https://github.com/GAS85/ssh-auth-logger/actions/workflows/go-test.yml)
[![Release Build and Push to Dockerhub](https://github.com/GAS85/ssh-auth-logger/actions/workflows/docker-release.yml/badge.svg)](https://github.com/GAS85/ssh-auth-logger/actions/workflows/docker-release.yml)
[![codecov](https://codecov.io/gh/GAS85/ssh-auth-logger/branch/main/graph/badge.svg)](https://codecov.io/gh/GAS85/ssh-auth-logger)
[![Docker hub](https://img.shields.io/badge/Docker--hub-grey?logo=docker)][docker-hub]
[![Docker Pulls][docker-pulls]][docker-hub]
[![Docker Image Size][docker-size]][docker-hub]
[![Docker Image Size][docker-size]][docker-hub]

Donations:
[![Buy me a coffee](https://img.shields.io/badge/Buy_me_a_coffee-grey?logo=buymeacoffee)](https://buymeacoffee.com/georgiy.sitnikov)
[![PayPal](https://img.shields.io/badge/Paypal-grey?logo=paypal)](https://www.paypal.com/paypalme/GeorgiySitnikov)
[![Github Sponsors](https://img.shields.io/badge/Github_sponsors-grey?logo=github)](https://github.com/sponsors/GAS85)

[docker-hub]: https://hub.docker.com/r/gas85/ssh-auth-logger
[docker-pulls]: https://img.shields.io/docker/pulls/gas85/ssh-auth-logger?logo=docker
[docker-size]: https://img.shields.io/docker/image-size/gas85/ssh-auth-logger/latest?logo=docker

## Interesting features

### Structured logging

ssh-auth-logger logs all authentication attempts as json making it easy to consume in other tools.  No more ugly [openssh log parsing vulnerabilities](http://dcid.me/texts/attacking-log-analysis-tools.html).

### "Random" host keys

ssh-auth-logger uses HMAC to hash the destination IP address and a key in order to generate a consistently "random" key for every responding IP address.  This means you can run ssh-auth-logger on a /16 and every ip address will appear with a different host key. Random sshd version reporting as well.

### AbuseIPDB Reporting

Optionally ssh-auth-logger will report IPs to the [AbuseIPDB](https://www.abuseipdb.com).

### Example log entry

This is normally logged on one line

```json
{
  "client_version": "SSH-2.0-libssh2_1.4.3",
  "destinationServicename": "sshd",
  "dpt": "2222",
  "dst": "192.168.1.2",
  "duser": "root",
  "level": "info",
  "msg": "Request with password",
  "password": "P@ssword1",
  "product": "ssh-auth-logger",
  "server_version": "SSH-2.0-dropbear_2019.78",
  "server_key_type":"ssh-rsa",
  "spt": "38624",
  "src": "192.168.1.4",
  "time": "2017-11-17T19:16:37-05:00"
}
```

### Example AbuseIPDB Report comment

This is normally reported IP comment:

```plain
SSH authentication brute-force attempt GAS85/ssh-auth-logger honeypot
```

If you enable User names reporting, it will be add:

```plain
SSH authentication brute-force attempt GAS85/ssh-auth-logger honeypot; usernames=["flash" "git" "root" "wordpress" "dci" "andong" "mars" "dylan"]
```

If you enable Passwords hashes reporting, it will be add:

```plain
SSH authentication brute-force attempt GAS85/ssh-auth-logger honeypot; usernames=["flash" "git" "root" "wordpress" "dci" "andong" "mars" "dylan"]; passwords_sha1=["0bddc96375f465f6fd6462cc9481ab7605fe40b1" "060b3b99f88e96085b4a68e095bc9e3d1d91e1bc" "96900d99a52db0558d15a37766a4125762b75ac6" "94510c89ec1e494522c303497e6a6c0e71961f6a" "7f2c116fbdea1207e84a4ce066ce1617c1940ea6" "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" "5036854299afc07432c453b340971eee638a585b" "0cf05b6e4c2b64372848a1d36afc00b36dd696ff" "937ab279a60dcaac3ba1b419b6ce1ecf7ec0a642" "a33a2383c34c63e28b3420cf30d644d9936d0af5"] 
```

You can enable plain passwords reporting via `ABUSEIPDB_REPORT_CLEAR_PASSWORD`, but this is **not recommended**, please report hashes instead.

```plain
SSH authentication brute-force attempt GAS85/ssh-auth-logger honeypot; usernames=["flash" "git" "root" "wordpress" "dci" "andong" "mars" "dylan"]; passwords=["123456" "123" "1234" "password" "12345678" "merry" "1234" "root] 
```

## How to use it

```shell
go install github.com/GAS85/ssh-auth-logger:latest
export SSHD_BIND=:2222
~/go/bin/ssh-auth-logger
```

## Note

To bind to port 22 directly:

```shell
sudo setcap cap_net_bind_service=+ep ~/go/bin/ssh-auth-logger
```

## Docker

### Run with docker

Bind to port 2222 in a host machine

```shell
docker run -t -i --rm  -p 2222:2222 gas85/ssh-auth-logger:latest
```

Test connections

```shell
ssh user@localhost -p 2222 -o StrictHostKeyChecking=no -o PubkeyAuthentication=no -o UserKnownHostsFile=/dev/null -o NumberOfPasswordPrompts=10
```

### Run with Docker compose

Docker compose example:

```yaml
# Create isolated network
networks:
  isolated_net:
    driver: bridge

services:
  ssh-auth-logger:
    image: gas85/ssh-auth-logger:latest
    container_name: ssh-auth-logger
    environment:
      - TZ=Europe/Berlin                       # You can set Time Zone to see logs with your local time
      # Following are default values
      # SSHD Part

      #- SSHD_RATE=500                         # bits per second, emulate very slow connection
      #- SSHD_BIND=:2222                       # Port and interface sshd to listen
      #- SSHD_KEY_KEY="Take me to your leader" # It's a secret key that is used to generate a deterministic hash value for a given host IP address
      #- SSHD_MAX_AUTH_TRIES=6                 # The minimum number of authentication attempts allowed
      #- SSHD_RSA_BITS=3072                    # If you use 'rsa' you can also set RSA key size, 2048, 3072, 4096 (very rare)
      #- SSHD_PROFILE_SCOPE=host               # Can be 'remote_ip' (each remote IP gets its own profile, simulating per-attacker behavior.), or anything else for 'host' (the same local host always gets the same profile, e.g. binding to 0.0.0.0:22 will always select the same Profile).
      #- SSHD_SEND_BANNER=false                # Send SSH Login Banner before Password prompt
      #- SSHD_LOG_CLEAR_PASSWORD=true          # Log Passwords as clear text or Base64 coded
      #- SSHD_LOGS_FILTER=""                   # Comma-separated list of allowed fields. 'msg', 'level' and 'time' can't be removed. Following combinations are possible: "duser,src,spt,dst,dpt,client_version,server_version,password,keytype,fingerprint,server_key_type,destinationServicename,product"
      #- FORCE_SSH_PROFILE=dropbear            # Force profile to use, please refer to "serverProfiles" in main.go. Possible values: dropbear, OpenSSH_7.4, OpenSSH_7.9, OpenSSH_8.2, OpenSSH_8.4, OpenSSH_9.6. THERE IS NO DEFAULT VALUE FOR IT, it is not set --> all Profiles are used.

      # Telnet Part

      #- TELNET_BIND=:2323                     # Port and interface telnetd to listen
      #- TELNET_LOG_CLEAR_PASSWORD=true        # Log Passwords as clear text or Base64 coded
      #- TELNET_RATE=100                       # bits per second, emulate very slow connection

      # AbuseIPDB Part

      #- ABUSEIPDB_ENABLED=false               # Enable Abuse IP DB reporting
      #- ABUSEIPDB_API_KEY=someKey             # Your Abuse IP DB API Key. Get one after registration: https://www.abuseipdb.com/account/api/keys
      #- ABUSEIPDB_ATTEMPTS=10                 # Attempts amount when IP will be reported 
      #- ABUSEIPDB_REPORT_INTERVAL=15m         # How often shall we report the same IP. 15 minutes is a minimum. Please refer to Rate Limit in https://www.abuseipdb.com/api.html
      #- ABUSEIPDB_SSH_CATEGORIES=18,22        # SSH Report categories, please refer to https://www.abuseipdb.com/categories
      #- ABUSEIPDB_TELNET_CATEGORIES=14,18,23  # Telnet Report categories, please refer to https://www.abuseipdb.com/categories
      #- ABUSEIPDB_CLEANUP_INTERVAL=30m        # Internal IP table clean up interval
      #- ABUSEIPDB_STATE_EXPIRY=2h             # Interval when we will forget about IP's login attempts prior to report it
      #- ABUSEIPDB_REPORT_CLEAR_USERNAME=false # Report User names to AbuseIPDB in a clear text
      #- ABUSEIPDB_REPORT_HASHED_PASSWORD=true # Report hashed Passwords to AbuseIPDB
      #- ABUSEIPDB_REPORT_CLEAR_PASSWORD=false # Report Passwords to AbuseIPDB in a clear text. It is strongly recommended to use ABUSEIPDB_REPORT_HASHED_PASSWORD instead. Works only when report of hashed password is disabled
    volumes:
      # Mount log file if needed
      - /var/docker/ssh-auth-logger/log:/var/log
    ports:
     - 2222:2222 # SSH Auth Logger
     - 2323:2323 # SSH Auth Logger Telnet
    networks:
      # Use isolated docker network, so that other containers will be not reachable from it
      - isolated_net
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 100M
    # Health check is build in, so you do not needed it. Use only if you will set different test or parameters.
    # healthcheck:
       # Will test if port application is up AND log file was not vanished by host machine log rotate
    #   test: nc -zv localhost:$$SSHD_BIND && test -s /var/log/ssh-auth-logger.log || exit 1
    #   interval: 5m00s
    #   timeout: 5s
    #   retries: 2
    #   start_period: 5s
    logging:
      driver: json-file
      options:
          max-size: 10m
```

## Build local

Fork this project and then execute:

```shell
go install .
```

### Test local

To test this project you can run:

```shell
go test ./... -v
```

## fail2ban configuration

To configure [fail2ban](https://github.com/fail2ban/fail2ban) you have to create a filter:

```shell
sudo nano /etc/fail2ban/filter.d/ssh-auth-logger.local
```

with following content:

```shell
[Definition]
_daemon = ssh-auth-logger

# Match JSON log line with a "time", "msg" fields and a "src" IP
failregex = ^.*"msg":"Request with (password|key)".*"src":"<HOST>".*$
            ^.*"msg":"Telnet login attempt".*"src":"<HOST>".*$

datepattern = %%Y-%%m-%%dT%%H:%%M:%%S(?:Z|%%z)

ignoreregex =
```

The you have to update your `jail.local`:

```shell
sudo nano /etc/fail2ban/jail.local
```

with following config:

```shell
[ssh-auth-honeypot]
enabled = true
filter = ssh-auth-logger
action = iptables-allports
         # Additonally you can setup abuseipdb reporting as per https://github.com/fail2ban/fail2ban/blob/master/config/action.d/abuseipdb.conf
         # Or directly with ssh-auth-logger
         #abuseipdb[abuseipdb_category="18,22"]
# Docker mount log to the localsystem
logpath = /var/docker/ssh-auth-logger/log/ssh-auth-logger.log
# maxretry should be equal or more than in a SSHD_MAX_AUTH_TRIES
maxretry = 6
# For very slow attacker that tries 3 passwords per day
findtime = 1d
# Ban time can be anything you like
bantime = 1d
```

After that you have to reload your fail2ban with command:

```shell
sudo fail2ban-client reload
```
