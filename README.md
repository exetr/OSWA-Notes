# OSWA-Notes

Notes for the ThinkSECURE Organizational Systems Wireless Analyst (OSWA) Certification. Information here was sourced from both study guides provided by ThinkSECURE and personal anecdotes from the March 2019 run of the certification examination.

NOTE: *Information listed here may not accurately reflect content that is involved in any particular runs of the examination*

## Table of Contents

## Introduction

The examination duration is 3 hours long and contains 20 multiple choice questions with five options. There may be more than one correct answer, no correct answers or all five correct options for each question. For every option that is correctly selected, 1 mark is awarded, and for every incorrect option that is selected, one mark is deducted. To effectively answer a question, you must ensure that the `Answer?` checkbox is checked. If it is not checked, you will be awarded 0 marks for that question since it is considered that you have not chosen to answer that question. 

The passing score is 60%, meaning that you would need to answer at least 12 questions with fully correct. Within the 20 questions, there are about 4 questions that are purely theoretical in nature, with the others requiring interaction with the network to answer them. Since this examination involves negative marking, I highly suggest that you do not answer questions that you are completely uncertain of as trying to guess answers to questions brings a higher chance of getting the answers wrong and hence getting more marks deducted. The only exception is with questions that have only one possible correct answer. In this case, ensure that you at least choose to answer the question, as even if you leave no options checked, you will score a maximum of three points for that particular question.

For the examination, you will be provieded remote access to a network provisioned by ThinkSECURE 

## Course Content

This section contains the information included in the training programme for the certification.

### 1. Why Wireless Network Penetration Testing & Vulnerability Assessment

#### 5E Attacker Methodology

##### Exploration

Exploration is usually the first phase in an attacker's attempt to understand more about the target he/she intends to attack. This may involve finding out information such as 
- Are wireless networks in use by the target?
- What is their network name (SSID)?
- Where is their location and coverage?
- Is it a private or public network?

##### Enumeration

This is the next step in an attacker's attempt to determine as many weaknesses as possible resident in the target he intends to launch an attack against. Wirelessly, this involves, but is not limited to:
- Is the network secured using encryption?
- What type of encryption is used?
- Are all access points using the same encryption schema?
- Does the implementation have specific vulnerabilities? (eg ARP replay, weak passphrases, DoS potential)
- Are there active clients connected and/or generating traffic?
- Do the active Clients have wireless profiles other than the profile for the target?
- Is proximity access possible or must the attacker use range extenders?

##### Exploitation

Once a target has been enumerated, the attacker shifts to the exploitation phase, in which he attempts to penetrate or disrupt the target using any weaknesses found during enumeration. Wirelessly, this involves the following actions
- Running specialised exploitation tools against the wireless network (depending on the type of encryption used)
- Running specialised exploitation tools against the wireless client (with the aim of using them as a jump off point or for information theft)
- Running denial-of-service tools in conjunction with the above to increase chances of successful exploit

##### Embedding

Once a wireless target has been penetrated by an attacker, they will seek to retain access. Embedding covers actions taken by the attacker to reatin access in case of future need, often established using differernt means as the exploit used in gaining the initial access. Actions shift from wireless towards wired host/network scanning and trojan, rootkit or backdoor installation.

##### Egress

Egress involves removing evidence that could indicate an attacker's presence. Wireless auditors are usually not required to embed software into production systems within the network, once it is proven that an attacker can exploit a wireless network, the wireless penetration test objective has been achieved, as such the wireless auditor is primarily concerned with the first 3Es of the 5E methodology.

#### Vulnerability Assessment vs Penetration Testing

VA is accomplished by performing exploration and enumeration actions, it involves finding out what types or versions of hardware and/or software thar are present and what type of vulnerabilities they are likely to contain. However, there is no way of actually confirming if they exist until actual exploitation attempts are carried out.

A PT is more comprehensive as it actually confirms whether the suspected vulnerability is really present on a target, however, it also carries the risk of outage occuring on the target.

### 2. Radio Frequency Fundementals

#### Definitions

- **Wavelength**: The distance the wave goes in 1 cycle (time between a wave's start and next wave's start), measured in distance between midpoints of RF sine waveform, calculated using `speed = frequency * wavelength` and `frequency = 1/period`
- **Diffraction**: The ability of radio waves to turn sharp corners and bend around obstacles, results in a change of direction of part of the EM energy around edges of encountered obstacles, wavelengths longer than the diameter of an obstruction easily propogate around it, wavelengths shorter than the obstruction diameter suffer increasing attentuation, at some point a shadow zone develops which is an RF void on the lee-ward side of the obstruction between the transmitter and the receiver.
- **Isotrophic Radiator**: Hypothetical, lossless antenna having equal radiation intensity in all directions, used as 0dB gain reference in directivity calculation
- **Gain**: How much of a signal you can favor in a vertain direction compared againsta n isotrophic radiator, a measure of directionality. The greater the gain, the longer and flatter the signal pattern. As gain increases, distance in the lateral plane increases. Long range antenna designs focus emanations in certain direction at expense of all-round coverate. As beam becomes narrower, accuracy of beamwidth decreases.
- **3dB Rule**: When power is doubled, 3dB is gained, when power is halved, 3dB is lost.
- **Power & Distance**: The higher the power output for a given RF signal, the further it goes, to extend transmission range, increase power but can only increase until PCBs cannot handle heat. Transmisson range != reception range, impacted by antenna design, IC processing algorithm, TX power, attenuation, this applies to both sender and receiver.
  - Sensitivity determined using the formula `dBm = log(mW) * 10`, negative values imply greater sensitivity
- **Attentuation**: Defined as the reduction of signal strength during transmission, path loss, attenuation of EM wave in transit between transmitter and receiver is affected by: distance between TX and RX antennas, LOS between TX and RX antennas, antenna height, environmental variables. Attenuation can be measured with the formula `10 * log(mW exiting media / mW entering media)`, free space loss can be measured using the formula `32.4 + 20 log(frequency) + 20 log(distance)`. Calculating attenuation in enclosed areas is difficult as indoor signals bounce off obstacles (reflection), enter different materials at different angles (refraction) and enter different materials with different thermal conversion properties (absorption). Attenuation is not linear, it grows exponentially as range increases. Environmental variables causing path loss can be categorised as follows:
  - **Free-Space Loss**: Attenuation if all absorbing, obstructing, refracting and reflecting influences are sufficiently removes so as to have no effect on RF signal propogation, primarily caused by beam divergence through air medium
  - **Medium or Coupling Loss**: Joints, connectors, wire resistance, etc
  - **Reflection**: RF bouncing off material due to angle of attack
  - **Refraction**: RF retardation and directional change caused by dissimilar materials with dissimilar refractive indices or density
  - **Absorption**: Conversion of transmitted RF energy into another form, usually thermal, due to interaction between incident energy and material medium at molecular or atomic level
- **Interference**: Defined as signals transmitting at same frequency but with different code, reception quality and ease determined by signal-to-noise ratio. One attempt to mitigate is to segregate spectrum into multiple bands or channels and forcing the selection of a channel to talk, however can be affected by devices which are not talking same protocol or code, yet transmitting on same frequency, furthermore, subdividing a spectrum does not guarentee non-interference from adjacent bands. 
  - 802.11 specifications specify only centre frequency of channel and spectral mask for it, a sufficiently powerful transmitter can extend beyond spectral mask. Thus, *it is wrong to say that channels 1, 6 and 11 do not overlap*.

#### RF Spectrum Analysis

Observation of degree of electromagnetic activity in RF spectru, more sources of EM energy present in any given portion of RF spectrum, the more interference or noise will be present, degrading communication performance and efficiency as receiver will have to filter off noise before sending filtered signal onwards for upper-layer analysis.

- **Colours**: From extremely strong to extermely weak: Red, yellow, light blue, dark blue
- *A spectragraph cannot tell you the distance to a particular transmission source, all it tells you is that for a given piece of hardware you are using, a particular RF energy signal on a particular frequency at a particular point in time is of a certain signal strength.
- To identify origin of particular signal, move around and determine the relative increase or decrease in signal strength.

#### Sphere Of Influence Limit (SOIL)

Defined as the maximum rance to which a given transmitter at a given transmission power rating is able to actually reach such that any upper layer communication protocols are able to handshake

- **Maxmium SOIL**: Maximum range where communications link between TX and RX can be physically maintained
- **Signal Reacquisition SOIL**: Minimum range where RX can successfully reassociate with TX

Attackers are usually concerned about SR-SOIL, users more concerned about MAX-SOIL. SOIL helps to establish the area of coverage of a given device, to determine if there is enough signal leakage that someone may be able to acquire the signal, decode the contents at a higher layer and proceed to sufficiently safe distance to carry out any exploratory, enumatory and exploitary work. Once an attacker's connection is dropped (moves beyond MAX-SOIL), he or she will have to get much closer to the AP before reassociation (SR-SOIL)

#### IEEE 802.11 Channels

|Channel|Frequency|Remarks|
|---|---|---|
|1|2.412 GHz|Often used as non-overlapping channel|
|2|2.417 GHz||
|3|2.422 GHz||
|4|2.427 GHz||
|5|2.432 GHz||
|6|2.437 GHz|Often used as non-overlapping channel|
|7|2.442 GHz||
|8|2.447 GHz|Microwave (~2.45 GHz)|
|9|2.452 GHz||
|10|2.457 GHz||
|11|2.462 GHz|Often used as non-overlapping channel|
|12|2.467 GHz||
|13|2.472 GHz||
|14|2.477 GHz|Often used as non-overlapping channel|

### 3. Wireless Networking Protocols, Equipment & Security Issues

#### Bluetooth

802.15, also knwon as Bluetooth specifies a personal local area network (PAN), main users in cellphones, PDAs. There are 3 distinct performance categories: Class 3 - <10 m, Class 2  - >10m and <100m and Class 3 - >100m.

It is popular as it can be always activated, can automatically connect to devices in range, no LOS is required and is widely supported by consumer-grade devices. However, it is low bandwidth and the security model makes a few assumptions. Firstly, OBEX protocol is designed for information, as such, ease of use is paramount. Bluetooth SIG's concept of security assumes hacking into an existing, established connection, if the attacker is the one initiating pairing, there would be no defences against frequency hopping and no encryption of channel.

##### Bluetooth Attacks

- **Bluesnarf**: Theft of information from devices
- **Bluedoor**: Abuse of pairing mechanism, removed device not actually removed from register, no restrictions once authenticated
- **Bluejacking**: Sending of message, does not involve any kind of hijacking
- **Bluebug**: Access gained to AT command set of device, providing full access to higher level commands and channels, such as data, voice and messaging
- **Bluesmack**: Attempted DosS using L2PING with oversized packets
- **Carwhispering**: Attacking bluetooth headsets that allow more than one pairing to record or play messages
- **Bluetooth Worms**: CommWarrior.Q, Inqtana.A

Bluetooth attacks are not as common as 802.11-based attacks, still presents potential risk. Bluesnarfing expeditions to senimars and conferences and grabbing CEO's phonebook info, dialed numbers, and system admins who keep information on bluetooth enabled PDAs. Bluetooth works may result in large bills when mass sending MMS.

Defences include manufacturer's fixes for bluesnar, explicitly keep bluetooth off unless initiating a connection, set to non-discoverable mode, change default name to something non-identifiable, use headsets that do not allow more than one simultaneous pairing, when disposing of phones, perform battery reset to permanently remove pairing, patch firmware if available.

#### Radio Frequency Identification (RFID)

RFID is a method of remotely storing and retrieving data using devices called RFID tags, small objects which contain antennas to enable them to receive and respond to RF queries from a RFID interrogator. The RFID infrastructure typically consist of tags (store and provide information), tag programming stations (tag writers), interrogators (readers detecting tags and information) and backend systems (database, middleware, etc). 

#### RFID Tags

- **Passive**: No power source, energy comes from transponder's RF energy to reflect a response, small and compact, range up to 5 meters
- **Semi-Active**: Battery assisted backscatter, increases read range to up to 100m
- **Active**: High power source required, longer range, can store more information, can initiate communications, range can be up to 10km

Tag maximum read range depends on: reader antenna size, tag antenna(s) size, reader RF power, environmental noise, tag orientation to the reader (full frontal or angled). RFID tags use categories usually fall into: identification, access control, tracking, billing. 

#### RFID Security

The security of RFID can be from two perspectives:
- **Deployer**: Reprogramming tags (frontend or backend theft, authentication, encryption), DoS (RF injection or flooding), redundancy (battery life or read failure), accuracy & throughput (data integrity)
- **Carrier**: Privacy, politics, crime, health

No global government body governs RFID frequencies, each countries owns its own air and can set its own rules.

Anyone who knows an RFID tag exists can capture its numerical information, all that is required is a tag reader. Data in many cases not encrypted, vendors frequently post tag specifications and structure information, readers operating at currect frequencies often able to understand the structure. Attackers may even attempt to pass SQL statements embedded in the tag to corrupt backend databases. Defences and mitigation strageties for the risks can include:
- **Deployer**
  - Encryption of tag data
  - Tag-deactivation upon area egress
  - Layered security at the backend
  - Procedural security for RFID-protected physical access
- **Carrier**
  - Metal enclosure around tags
  - Counter RF emanation
  - Just say no 
 
#### IEEE 802.11

Commonly known as WiFi (Wireless Fidelity).

##### Terminology

- **Wireless LAN (WLAN)**: Local network area made up of series of APs interconnected by CAT5 cabling or wireless repeaters, through which a WLAN network adapter can access
- **Access Point (AP)**: Layer 1 device similar to a hub for WLANs
- **Wireless Repeating**: Capability of equipment to extend network coverage via RF where wired connectivity is impossible or not cost-effective, involves AP being paired with another to form extended WLAN for user access.
- **Ad-Hoc Mode**: Peer-to-peer WLAN setup comprised of multiple WNICs to establish connectivity between themselves without need for AP
- **Basic Service Set (BSS)**: A group of 802.11 stations
- **Independent Basic Service Set (IBSS)**: Network in ad-hoc mode with wireless clients without access point
- **Infrastructure Mode**: Use of AP's local relaying device to other stations/networks, all stations talk through APs, not directly to each other
- **Distribution System (DS)**: Means by which AP talks with other APs to exchange frames for stations in their respective BSSes, forward frames to follow mobile stations as they move from one BSS to another and exchanges frames with a wired network.
- **Basic Service Set ID (BSSID)**: MAC address of AP's radio component. Some APs use different addresses for radio component and wired ethernet port, addresses are likely to be sequential.
- **Extended Service Set (ESS)**: Set of infrastructure BSSes whose APs communicate amongst themselves to forward traffic from one BSS to another to facilitate movement of mobile stations between them.
- **Service Set Identifier (SSID)**: Description given to AP's individual sphere of radio influence which describes that AP's network name, every AP has one, sometiles labelled as Extended SSID consisting of multiple APs with same SSID from the basis of ESS WLAN in which users can roam between APs.
- **Roaming**: Act of disassociating from one AP and associating to another BSS within the ESS
- **Association/Disassociation**: Connecting and disconnecting from an AP as you enter and leave its RF sphere of influence.
- **SSID Broadcasting**: Causes an AP to show SSID in frame beacons for any WNIC to detect and connect to, not a good idea unless user is running hotspot.
- **WEP, WPA-PSK, WPA, WPA2**: Frame payload encryption standards and mechanisms used to provide confidentiality of data.
- **Master Mode**: WNIC operates as AP, useful for testing wireless client security
- **Monitor Mode**: WNIC operates in RFMON mode, 802.3 promiscuous NIC equivalent. Monitor mode allows you to sniff frames off the air and dump the output to a pcap file.

When doing wireless auditing, chipset is important. Brand is insignificant, need a chipset that is natively supported by Linux. Divers and firmware are needed to support frame injection which is necessary to conduct replay and deauthentication attacks.

##### Wireless Frame Architecture & Analysis

802.11 MAC Layer also handles acknowledegement, packet retransmission and fragmentation, has Carrier Sense Multiple Access with Collision Avoidance (CSMA/CA) with positive acknowledgements.

- Virtual Carrier Sense: Request-To-Send (RTS) and Clear-To-Send (CTS), both update NAV duration and work with CSMA/CA in sensing medium
- Send & Wait: Cannot send frame fragment until ACK is received, if none received, entire frame is dropped

##### Frame Control Headers

| Type | Type Description | Subtype | Subtype Description |
|------|------------------|---------|---------------------|
|00|Management|0000|Association Request|
|00|Management|0001|Association Response|
|00|Management|0010|Reassociation Request|
|00|Management|0011|Reassociation Response|
|00|Management|0100|Probe Request|
|00|Management|0101|Probe Response|
|00|Management|1000|Beacon|
|00|Management|1010|Disassociation|
|00|Management|1011|Authentication|
|00|Management|1100|Deauthentication|
|01|Control|||
|10|Data|||
|11|Reserved|||

- **ToDS**: Bit set to 1 when frame is addressed to AP for forwarding to Distribution System, includes case where destination is in same BSS and AP is relaying frame.
- **FromDS**: Bit set to 1 when frame is coming from DS (passed on by AP). 
- *Additional bits omitted*

Both ToDS and FromDS are set to 0 for management and control frames and when in ad-hoc mode, set to 1 only where frame is being transmitted from 1 AP to another in a WDS (bridge or repeater mode)

##### Association Process
```
       | --------- Probe Request --------> |
       | <-------- Probe Response -------- |
       | ---- Authentication Request ----> |
Client | <--- Authentication Response ---- | AP
       | ------ Association Request -----> |
       | <----- Association Response ----- |
       | <--------- Data Traffic --------> |
```

### 4. Wireless Security Testing - Infrastructure

#### 802.11i

802.11i covers wireless security. It has the following encryption schemas:
- **Wired Equivalent Privacy (WEP)**: 40 Bit and 104 Bit Keys (add 24 Bit IV)
- **WiFi Protected Access**: Pre-Shared Key and Enterprise (TKIP)
- **WiFi Protected Access 2**: Pre-Shared Key and Enterprise (CCMP)

802.11i also has authentication components, and is controlled by AuthenticationType parameter of 802.11 management frame:
- **Open**: Default null algorithm involving identity assertion and authentication request followed by authentication response
- **Shared Key**: Challenge-response handshake using values derived from WEP Keys.

#### WEP Analysis

WEP revolves around RC4 encyrption algorithm, is a stream cipher encrypting data as it is feed in via a XOR operation. Cipher is made up of 2 components, a random initialisation vector and a pre-shared key, also utilising a cyclic redundancy check to test integrity of transmitted packet.

Vulnerability is in implementation of encryption. When there is IV collision, contents can be XORed to retrieve it in plaintext. Deauthentication attacks can also be carried out to speed up the capturing of IVs in networks with little traffic.

In defending against WEP attacks, even with MAC address filtering, disabling SSID broadcast, limiting RF transmit power, there is no effective defence if relying solely on WEP. As such, users should no longer use WEP.

#### WPA-PSK & WPA2-PSK Analysis

Client sends PSK which forms part of Pairwise Master Key (PMK), derived from `PBKDF2(passphrase,ssid,ssidLength)`. PMK of client and AP are combined twith 2 nonces for 2 packets of the 4-way EAPOL handshake to derive the Pairwise Transient Key (PTK), a hashed value which is used to encrypt the data flow.

The 4-way handshake takes place after association request & response in association process. The four messages include:
1. AP sends to supplicant a nonce, ANonce
2. Supplicant creates nonce and calculates PTK, sends SNonce and security parameters to AP
3. AP sends supplicant security parameters found in beacon and probe responses.
4. Indication that temporal keys are now in place to be used.

However, most AP vendors only allow single PSK, thus a single PMK which is used to produce PTK. 4-way handshakes can be sniffed together with deauthentication attacks to obtain packet captures. Dictionary attacks can be run against to obtain passphrase.

Defences against attacks include:
- Passphrases longer than 20 characters
- Alphanumerical and symbolical passphrases
- Passphrases should be translation of non-English dialect
- Passphrases should not be related to person, company or entity that AP belongs to
- Temporal Key rotation shoule be made as often as possible, including forcing re-keying whenever user joins or leaves letwork, in addition to MAC and IP address filtering and disabling SSID broadcase

#### WPA & WPA2 Enterprise Analysis

Also known as Robust Secure Network (RSN), has an EAP authentication schema generating 256-bit PMK instead of PSK, 802.1x functionality also incorporated. Comprises of 3 components: supplicant, authenticator and authentication server. Supplicant will authenticate with the authentication server through authenticator. Authenticator does not need to perform authentication, it only exchanges information between supplicant and authentication server.

This however requires more resources compared to WPA-PSK. Traffic encryption is also weak so sniffing is made easier. This is addressed through Extensible Authentication Protocol (EAP) family, EAP-TLS, EAP-TTLS and PEAP, which establishes a protected means of encrypting the authentication credentials.

Generally, the components required include: 802.1x compatibel client wireless network adaptors, client supplicant capable of EAP, wireless AP compatible with 802.1x and EAP, RADIUS server compatible with EAP, PKI.

Attackers can still try to trick clients into revealing the challenge-response pair by setting up fake RADIUS servers and getting the client to authenticate with them instead of the legitimate server. Defences against attacks include:
- Enabling validation of server certificates
- Specification of IP address of authentication server
- Establish local Certificate Authorities
- Disable user permission to authorise new servers

Additionally, mixed-mode WPA is discouraged and there is a lack of ad-hoc mode.

#### 802.11 Based Denial of Service

Clients perform handshakes with APs as part of the association process. This is a possible area of exploit to perform DoS attacks, specifically with the use of authentication/deauthentication and association/disassociation requests and responses. Againts APs, try to flood them with handshaking traffic until the point where they cannot handle legitimate requests. Against clients, deauthentication frames are weapon of choice, as nature of 802.11 protocol specification means that management frames have no security mechanisms for validating senders, this it s is easy to spoof an AP to deauthenticate a client.

In its current form, 802.11w adds cryptographic protection to deauthentication and disassociation frames to prevent spoofing. Security association is also added to prevent spoofed association or authentication requests from disconnecting an already connected client. However, this only works for WPA2 & WPA2-PSK setups as it uses EAPOL exchange to derive shared secret keys. Other attacks such as RF jamming, CTS attacks are not covered by 802.11w schema.

### 5. Wireless Security Testing - Client

We must also consider the client-end of things, it is often easier to compromise a wireless client, then use it to get into the corporate network, rather than brute-forcing the WLAN itself. Kismet and airodump can be used to detect probe packets.

#### Windows Slienet Adhoc Network Advertisement

When a user uses an AP at home with the SSID "netgear", the profile will be stored in the laptop. In a public location, when there is also a laptop configured as an ad-hoc network also with an SSID "netgear", the laptop will connect to this AP. The next time the user's laptop is booted up when there is no wired connection and no "netgear" SSID in range, the laptop will start advertising itself as an ad-hoc network with an SSID of "netgear".

#### WEP Client Communication Dumbdown (WCCD)

Certain WNIC driver implementations, after receiving an association response from an AP bearing privacy setting of 0 and where the association request was based off a profile setup to use WEP (setting of 1), will dumb down and associate with the AP using no encryption, where the correct response was not to associate at all.

This can be mitigated by:
- User Education (remove unused wireless profiles, use WPA, switch off wireless capabilities when not in use, learn how to read which wireless network machine is connected to)
- No Wireless Policy (purchase machines with no wireless capabilities, enforce no wireless client plugged into network, enforce via Windows AD group policy, install personal firewall, patch management)

### 6. Testing With A Twist

#### Ph00ling

Encompasses mirroring of SSG together with setting up of fake AP. Usually done by attackers to gain internet access, perform client-side attack, obtain attack platform, credit card fraud, credential theft. It is possible due to physical disconnects between user, attacker and network, RF signal strength race condition, requirement of usage credentials by operator, uneducated users. Reasons to conduct ph00ling include testing for employee awareness of policy, testing for certificate policy, implementation and awareness, testing for ease of attacker launching RF disassociation flood against WLAN and gaining RF supremacy.

The technique starts by crawling web portals for sites to mirror and hosting them locally. Secondly, the setup of DHCP and DNS servers to provide connectivity to the victim and to redirect all traffic back to the attacker. The attacker should also position himself/herself so that deauthentication frames and probe responses sent by the attacker can be received by the victim. 

Best results possible if attacker has at least 2 NICs, one to observe environment and one to perform deauthenticaiton attacks. This can be combined with web-based exploits that allow for remote code execution, with stealthiness depending on the payload being crafted into file and how the OS handles payload.

Defence against ph00ling include:
- Knowing what the real SSG portal looks like
- Checking IP addressing issued by real SSG
- Check page source for calls to weird CGI scripts
- Check authentic signed certificates with CA
- Cross check IP to MAC address assignment using `arp -a`
- When in doube, don't

#### Long Range Auditing

*Omitted*

### 7. MoocherHunting

Experts say that tracking of wireless clients are impossible due to reflection of wireless signals by walls or buildings, attentuation of wireless signals due to the environment and that attackers can change their MAC addresses.

#### Sprint-n-Drift Technique

Use power and rate of receipt of signals from wireless APs to determine the location of a suspected attacker. This technique is necessary to enable one man triangulation and to ensure the environment and characteristics in one location do not overly affect the track and give operator weighted false readings.

### 8. Concluding The Audit

- **Unexpected Results**: For situations that are outside the scope under test of unanticipated, refer to the client point-of-contace, with point in time dependendant on severity of issue, key to remember majority of wireless network audit engagements are likely to be based off IEEE 802.11 technologies, may contain other wireless technologies that present security issue. No one can cover nuances of every wireless technology, part of expert's skillset includes conducting research when faced with unfamiliar issue and to broaden education
- **Reporting Format and Procedure**: Done in a face to face manner, avoid sending an army - maximum of 3 from the testing team, testers who perform actual tests and audit project manager, executive summary and technical report should be delivered to client in a secure manner.

---

## References & Resources

[List of Linux Wireless Drivers](https://wireless.wiki.kernel.org/en/users/drivers)

[ThinkSECURE OSWA Assistant Compability](http://securitystartshere.org/page-software-oswa-assistant-platforms.htm)

[Chipset Lookup](http://linux-wless.passys.nl/)

[MAC Address Manufacturer Lookup](https://www.macvendorlookup.com/)

---

## Commands

This section contains commands for some of the operations you will encounter frequently during the training course and may come in handy during the examination.

### General

- Get IP Address from DHCP Server: `pump -i <interface>` or `dhclient`
- Get Routing Table: `route -n`
- Restart Interface: `ifconfig <interface> down && ifconfig <interface> up`

### Interface Configuration

#### Wireless Chipset Information
- `airmon-ng`
- `dmesg | less`
- `lspci -vv | less` *(For PCI Cards)*
- `lsusb --vv | less` *(For USB Chipsets)*

*Ralink Chipsets - rt___, Realtek Chipsets - rtl___, Atheros Chipsets - ar___*

#### Enabling Frame Injection (Ralink Chipsets)
- `iwpriv <interface> forceprism 1`
- `iwpriv <interface> rfmontx 1`

*This **MUST** be done for all Ralink Chipsets, else frame injection will not work properly*

#### Wireless Modes (Non-Atheros Chipsets) 
Non-Atheros Chipsets
- `iwconfig <interface> mode <type>`

Atheros Chipsets
- `wlanconfig ath0 destroy`
- `wlanconfig ath0 create wlandev wifi0 wlanmode <type>`

#### Set ESSID
- `iwconfig <interface> essid <ESSID>`

#### Set Channel
- `iwconfig <interface> channel <channel>`

#### Change Bands
- `iwpriv <interface> mode <number>`

*Usually, Mode 3 is for 802.11g, Mode 2 is for 802.11b, Mode 1 is for 802.11a*

#### List Discoverable APs
- `iwlist <interface> ap`
- `iwlist <interface> accesspoints`
- `iwlist <interface> scanning`

### Wireless Operations

#### Sniffing
- Start sniff: `airodump-ng <interface>`
- Start sniff and write to file: `airodump-ng <interface> -w <file>`
- Sniff targeted AP: `airodump-ng -c <channel> -w <file> --bssid=<BSSID> <interface>`

#### Deauthentication Attack
- Concept: 
- `aireplay-ng --deauth 500 -a <BSSID> -c <client MAC> <interface>`
- `aireplay-ng --arpreplay -b <BSSID> -h <client MAC> <interface>`

#### No-Client Associated Attacks - Interactive Replay Attack
- Concept:
- `aireplay-ng --fakeauth 15 -e <ESSID> -a <BSSID> -h <client MAC> <interface>`
- `aireplay-ng --fakeauth 5000 -o 1 -q 15 -e <ESSID> -a <BSSID> -h <client MAC> <interface>`
- 

#### No-Client Associated Attacks - PRGA-Packetforge-Interactive Attack
- Concept:

#### Configure Client to Join WEP AP (Non-Atheros Chipsets)

#### Configure Client to Join WEP AP (Atheros Chipsets)

#### Configure Client to Join WPA AP


#### Get IP Address
1. Use Wireshark to sniff traffic to get valid IP address ranges
2. Assign new IP address: `ifconfig <interface> <IP address> netmask <netmask>`
3. Set gateway: `route add -net 0.0.0.0 gw <gateway IP>`

### Cracking

#### WEP
- Korek (>500k IVs): `aircrack-ng -a 1 -b <BSSID> <filename>`
- PTW (>20k IVs or >40k IVs): `aircrack-ng -b <BSSID> <filename>`

#### WPA
- Default Attack: `cowpatty -f <dictionary-file> -r <packetdump-file> -s <SSID>`
- CoWPAtty Nonrestrict Mode: `cowpatty -2 -f <dictionary-file> -r <packetdump-file> -s <SSID>`
- Wireshark Cleanup: Using Wireshark, identify one valid 4-way handshake, mark and save as, run cowpatty on cleaned file
- Aircrack: `aircrack-ng -a 2 -e <SSID> -b <BSSID> -w <dictionary> <packetdump>`
- Retry: Rerun airodump-ng and deauthentication attacks until valid 4-way handshake is obtained

### AP Association

#### Open 

#### WEP

#### WPA

### Denial of Service