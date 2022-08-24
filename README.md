# Network-Security

## Josh Schauert Unit 11 Submission File: Network Security Homework 

### Part 1: Review Questions 

#### Security Control Types

The concept of defense in depth can be broken down into three different security control types. Identify the security control type of each set  of defense tactics.

1. Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?

    Answer: These are Physical Controls ( Physical Security )

2. Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?

    Answer: These are Management Controls ( Administrative Security )

3. Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?

    Answer: These are Operational Security Controls

#### Intrusion Detection and Attack indicators

1. What's the difference between an IDS and an IPS?

    Answer: IDS is Passive while IPS is Active
IDS alerts for potential attacks while IPS can actually take action against against the potential attacks

2. What's the difference between an Indicator of Attack and an Indicator of Compromise?

   Answer: Indicators of Attack happen in real time while indicators of Compromise indicate previous mailicious activity

#### The Cyber Kill Chain

Name each of the seven stages for the Cyber Kill chain and provide a brief example of each.

1. Stage 1: Reconnaissance ( Attakers probe for weakness - harvesting email addresses etc )

2. Stage 2:Weaponization ( build a deliverable payload using an exploit and backdoor ) 

3. Stage 3:Delivery ( Delivering the weaponized bundle to a victim via web, emai, usb etc )

4. Stage 4:Exploitation ( exploiting a vulnerability to execute code on a victims system )

5. Stage 5:Installation ( installing malware on a target system - EX: installing backdoor allowing you root access )

6. Stage 6:Command & Control ( C2 ) ( Command channel for remote manipulation of a victim ( Controls another computer ))

7. Stage 7:Actions ( Intruder accomplish original goals with "hand on keyboard" remote access )


#### Snort Rule Analysis

Use the Snort rule to answer the following questions:

Snort Rule #1

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
```

1. Break down the Sort Rule header and explain what is happening.

   Answer: Alerts user to any inbound TCP traffic from ports 5800 - 5820 on external network

2. What stage of the Cyber Kill Chain does this alert violate?

   Answer: Reconnaissance ( Attackers probing the system for weaknesses )

3. What kind of attack is indicated?

   Answer: Port Mapping ( Potential vnc scan 5900 - 5820 )

Snort Rule #2

```bash
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)
```

1. Break down the Sort Rule header and explain what is happening.

   Answer: the remote host through http ports tried to send a malicious payload to any port of the local machine ( http uses port 80 )

2. What layer of the Defense in Depth model does this alert violate?

   Answer:Delivery ( sending weaponized bundle to victim )

3. What kind of attack is indicated?

   Answer: Cross Site Scripting ( threat for policy Violation EXE or DLL Windows File Download )

Snort Rule #3

- Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the `msg` in the Rule Option.

    Answer: alert tcp $EXTERNAL_NET any -> $HOME_NET 4444 (msg:"tcp traffic detected port 4444";)

### Part 2: "Drop Zone" Lab

#### Log into the Azure `firewalld` machine

Log in using the following credentials:

- Username: `sysadmin`
- Password: `cybersecurity`

#### Uninstall `ufw`

Before getting started, you should verify that you do not have any instances of `ufw` running. This will avoid conflicts with your `firewalld` service. This also ensures that `firewalld` will be your default firewall.

- Run the command that removes any running instance of `ufw`.

    
    $ sudo apt remove ufw  
    

#### Enable and start `firewalld`

By default, these service should be running. If not, then run the following commands:

- Run the commands that enable and start `firewalld` upon boots and reboots.

    
    $ sudo systemctl enable firewalld.service 
    $ sudo /etc/init.d/firewalld start  
    

  Note: This will ensure that `firewalld` remains active after each reboot.

#### Confirm that the service is running.

- Run the command that checks whether or not the `firewalld` service is up and running.

    
    $ sudo systemctl status firewalld.service 


#### List all firewall rules currently configured.

Next, lists all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by not doing double work.

- Run the command that lists all currently configured firewall rules:

    $ sudo firewall-cmd --list-all  

- Take note of what Zones and settings are configured. You many need to remove unneeded services and settings.

#### List all supported service types that can be enabled.

- Run the command that lists all currently supported services to see if the service you need is available

    $ sudo firewall-cmd --get-services  

- We can see that the `Home` and `Drop` Zones are created by default.


#### Zone Views

- Run the command that lists all currently configured zones.

    $ sudo firewall-cmd --list-all-zones  

- We can see that the `Public` and `Drop` Zones are created by default. Therefore, we will need to create Zones for `Web`, `Sales`, and `Mail`.

#### Create Zones for `Web`, `Sales` and `Mail`.

- Run the commands that creates Web, Sales and Mail zones.

$ sudo firewall-cmd --permanent --new-zone=web  
$ sudo firewall-cmd --permanent --new-zone=sales  
$ sudo firewall-cmd --permanent --new-zone=mail  
$ sudo firewall-cmd --reload  
$ sudo firewall-cmd --permanent --list-all-zones 

#### Set the zones to their designated interfaces:

- Run the commands that sets your `eth` interfaces to your zones.

$ sudo firewall-cmd --zone=public --change-interface=eth0  
$ sudo firewall-cmd --zone=web --change-interface=eth1  
$ sudo firewall-cmd --zone=sales --change-interface=eth2  
$ sudo firewall-cmd --zone=mail --change-interface=eth3




#### Add services to the active zones:

- Run the commands that add services to the **public** zone, the **web** zone, the **sales** zone, and the **mail** zone.

- Public:

$ sudo firewall-cmd --permanent --zone=public --add-service=http  
$ sudo firewall-cmd --permanent --zone=public --add-service=https  
$ sudo firewall-cmd --permanent --zone=public --add-service=pop3  
$ sudo firewall-cmd --permanent --zone=public --add-service=smtp   

- Web:

$ sudo firewall-cmd --permanent --zone=web --add-service=http  

- Sales

$ sudo firewall-cmd --permanent --zone=sales --add-service=https 

- Mail

$ sudo firewall-cmd --permanent --zone=mail --add-service=smtp  
$ sudo firewall-cmd --permanent --zone=mail --add-service=pop3  




- What is the status of `http`, `https`, `smtp` and `pop3`?




SERVICES IMAGE HERE

#### Add your adversaries to the Drop Zone.

- Run the command that will add all current and any future blacklisted IPs to the Drop Zone.

$ sudo firewall-cmd --permanent --zone=drop --add-source=10.208.56.23  
$ sudo firewall-cmd --permanent --zone=drop --add-source=135.95.103.76  
$ sudo firewall-cmd --permanent --zone=drop --add-source=76.34.169.118 



#### Make rules permanent then reload them:

It's good practice to ensure that your `firewalld` installation remains nailed up and retains its services across reboots. This ensure that the network remains secured after unplanned outages such as power failures.

- Run the command that reloads the `firewalld` configurations and writes it to memory

sudo firewall-cmd --reload

#### View active Zones

Now, we'll want to provide truncated listings of all currently **active** zones. This a good time to verify your zone settings.

- Run the command that displays all zone services.

$ sudo firewall-cmd --get-active-zones




#### Block an IP address

- Use a rich-rule that blocks the IP address `138.138.0.3`.

$ sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="138.138.0.3" reject'



#### Block Ping/ICMP Requests

Harden your network against `ping` scans by blocking `icmp ehco` replies.

- Run the command that blocks `pings` and `icmp` requests in your `public` zone.

$ sudo firewall-cmd --zone=public --add-icmp-block=echo-reply --add-icmp-block=echo-request




#### Rule Check

Now that you've set up your brand new `firewalld` installation, it's time to verify that all of the settings have taken effect.

- Run the command that lists all  of the rule settings. Do one command at a time for each zone.

$ sudo firewall-cmd --zone=public --list-all  
$ sudo firewall-cmd --zone=sales --list-all
$ sudo firewall-cmd --zone=mail --list-all
$ sudo firewall-cmd --zone=web --list-all
$ sudo firewall-cmd --permanent --zone=drop --list-all







- Are all of our rules in place? If not, then go back and make the necessary modifications before checking again.

Yes everything is in place correctly

Congratulations! You have successfully configured and deployed a fully comprehensive `firewalld` installation.

---

### Part 3: IDS, IPS, DiD and Firewalls

Now, we will work on another lab. Before you start, complete the following review questions.

#### IDS vs. IPS Systems

1. Name and define two ways an IDS connects to a network.

   Answer 1: NIDS (Network-based Intrusion Detection System) monitors network traffic from all devices entering and exiting.
It analyzes traffic for trends and aberrant behaviors, and then sends a warning to the user.(Network TAP (Test Access Port): A hardware device that grants network access. Network TAPs send and receive data streams on different dedicated channels at the same time, ensuring that all data is received in real time by the monitoring device.) 

   Answer 2: The Host-based Intrusion Detection System (HIDS) scans the whole network for system data and malicious behavior on a single host. It can capture photos, and if these change maliciously over time, it will trigger an alert. It also examines the handling of changes in the operating system logs, files, and software, among other things.((SPAN/Mirrored Port)) A SPAN Port (Switched Port Analyzer) or Port Mirroring transmits a mirror image of all network data to another physical port, where the packets can be collected and examined.) 

2. Describe how an IPS connects to a network.

   Answer: An IPS analyzes traffic for suspicious behavior and is usually connected to a mirror port on a switch directly behind the firewall. 

3. What type of IDS compares patterns of traffic to predefined signatures and is unable to detect Zero-Day attacks?

   Answer: A signature based IDS is unable to detect zero day exploits. Since it compares traffic from a set of predetermined lists it lacks the functionality to filter anything outside of those domains.

4. Which type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?

   Answer: Anomoly based network intrusion detection is extremely beneficial for detecting suspicious traffic deviating from a well known baseline:

#### Defense in Depth

1. For each of the following scenarios, provide the layer of Defense in Depth that applies:

    1.  A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.

        Answer: Administrative ( Physical )

    2. A zero-day goes undetected by antivirus software.

        Answer: Technical ( Application )

    3. A criminal successfully gains access to HRâ€™s database.

        Answer: Technical ( Data )

    4. A criminal hacker exploits a vulnerability within an operating system.

        Answer: Technical ( Host )

    5. A hacktivist organization successfully performs a DDoS attack, taking down a government website.

        Answer: Technical ( Network )

    6. Data is classified at the wrong classification level.

        Answer: Administrative ( Procedures & Awareness )

    7. A state sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.

        Answer: Administrative ( Perimeter )

2. Name one method of protecting data-at-rest from being readable on hard drive.

    Answer: Drive Encryption

3. Name one method to protect data-in-transit.

    Answer: VPN or Public Key Encryption

4. What technology could provide law enforcement with the ability to track and recover a stolen laptop.

   Answer: GPS Tracking / "Find My" Technology

5. How could you prevent an attacker from booting a stolen laptop using an external hard drive?

    Answer: Disk Encryption w/ strong passwords / 2FA


#### Firewall Architectures and Methodologies

1. Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.

  Answer: There are a few , Circuit Level Gateways seems to be most common

2. Which type of firewall considers the connection as a whole? Meaning, instead of looking at only individual packets, these firewalls look at whole streams of packets at one time.

  Answer: Stateful Inspection Firewalls

3. Which type of firewall intercepts all traffic prior to being forwarded to its final destination. In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it?

  Answer: Application level gateways ( Proxy firewalls )


4. Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type- all without opening the packet to inspect its contents?

  Answer: Packet-filtering firewalls


5. Which type of firewall filters based solely on source and destination MAC address?

  Answer: Next Generation Firewalls ( Accomplished via data link / MAC Filtering )



### Bonus Lab: "Green Eggs & SPAM"
In this activity, you will target spam, uncover its whereabouts, and attempt to discover the intent of the attacker.
 
- You will assume the role of a Jr. Security administrator working for the Department of Technology for the State of California.
 
- As a junior administrator, your primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high priority alerts to senior incident handlers for further review.
 
- You will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling **Threat Intelligence** as part of your incident report.

#### Threat Intelligence Card

**Note**: Log into the Security Onion VM and use the following **Indicator of Attack** to complete this portion of the homework. 

Locate the following Indicator of Attack in Sguil based off of the following:

- **Source IP/Port**: `188.124.9.56:80`
- **Destination Address/Port**: `192.168.3.35:1035`
- **Event Message**: `ET TROJAN JS/Nemucod.M.gen downloading EXE payload`

Answer the following:

1. What was the indicator of an attack?
   - Hint: What do the details of the reveal? 

    Answer: Trojan Download ( JS. Nemucod ) - This trojan downloads additional malicious files onto a system. 


2. What was the adversarial motivation (purpose of attack)?

    Answer: Can download and install multiple varients of malware (Crowti, Tescrypt, Locky ( Ransomware ) Fareit ( Password and personal information stealer ) Ursnif ( records info about you and your computer )

3. Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table.

| TTP | Example | Findings |
| --- | --- | --- | 
| **Reconnaissance** |  How did they attacker locate the victim? Active reconnaissance ( hacker can use system info to gain access to protected digital materials )

| **Weaponization** |  What was it that was downloaded? Trojan Malware delivery ( Will download unwanted malicious software to attempt to steal information )

| **Delivery** |    How was it downloaded? Adversary controlled delivery ( was downloaded through an open port ) ( Can also be delivered via zip file in SPAM email )

| **Exploitation** |  What does the exploit do? Installs a malware downloader which downloads additional malware which will allow remote attacker execution

| **Installation** | How is the exploit installed? User must open the containing zip file and click the included javascript file which will trigger the install

| **Command & Control (C2)** | How does the attacker gain control of the remote machine?| When installed the malware "Phones Home" and either alerts access is possible or will steal and send data to its C&C server

| **Actions on Objectives** | What does the software that the attacker sent do to complete it's tasks?| it will download whichever varient of malware the attacker has specified and then execute that payload and send it back to the attacker. The commonly associated payloads are (Crowti, Tescrypt, Locky ( Ransomware ) Fareit ( Password and personal information stealer ) Ursnif ( records info about you and your computer )


    Answer: The attacker used the HTTP port to send TROJAN malware to obtain access to the system and install files that decrypt all of the data and prevent the machine from allowing any other access.
Attackers can demand a ransom in order to gain access to the data and other files on the network. 


4. What are your recommended mitigation strategies?


    Answer: Make sure all antimalware products are up to date, Enable MAPS , Maintain current blacklisted IP addresses associated with the malware , don't open javascript attachments in emails, use 2FA , Ensure a strong password policy , Turn on and maintain firewall, Limit user privileges


5. List your third-party references .

    Answer: https://www.certego.net/en/news/italian-spam-campaigns-using-js-nemucod-downloader/

https://www.f-secure.com/v-descs/trojan-downloader_js_nemucod.shtml

https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=JS/Nemucod

https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/91000/KB91905/en_US/McAfee_Labs_Threat_Advisory_JS-Nemucod.pdf

https://www.microsoft.com/security/blog/2016/05/09/gamarue-nemucod-and-javascript/

---

Â© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
