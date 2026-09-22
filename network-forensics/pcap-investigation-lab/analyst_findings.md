# PCAP Investigation - Analyst Findings

## Conversation 1

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** Low 
**Confidence:** Moderate 
**Analyst Notes:** Connection made to the Northstar portal.

---

## Conversation 2

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** Medium 
**Confidence:** High
**Analyst Notes:**  Confirmed SSH attempt, but a single SYN alone is not highly suspicious

---

## Conversation 3

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** Medium
**Confidence:** High 
**Analyst Notes:**  Second attempt to connect to SSH resource through port 22. No handshake was completed. 

---

## Conversation 4

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** Medium 
**Confidence:** High 
**Analyst Notes:**  Third attempt to connect to SSH resource through port 22. No handshake was completed.

---

## Conversation 5

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** Medium-High 
**Confidence:** High  
**Analyst Notes:**   Fourth repeated SSH SYN attempt to 10.10.20.40:22. None of the four attempts completed a TCP handshake. The pattern may indicate probing or repeated connection attempts, but intent is not established.

---

## Conversation 6

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** High
**Confidence:** High 
**Analyst Notes:**  10.10.20.17 established an external TCP/443 connection to 203.0.113.77 shortly after querying sync-update.example. This was the only TCP conversation in the capture containing application payload data. The evidence warrants additional investigation but does not independently prove malicious communication.

---

## Conversation 7

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** Medium-High
**Confidence:** Moderate
**Analyst Notes:**   The workstation established an external TCP connection to 203.0.113.88:8443. Port 8443 is commonly used for alternate HTTPS or application services. The completed handshake and unusual external destination warrant investigation, although no application payload was captured.

---

## Conversation 8

**Source:**  
**Destination:**  
**Service / Port:**  
**Handshake Completed:**  
**Payload Observed:**  
**Related DNS Activity:**  
**Investigation Priority:** Low 
**Confidence:** High 
**Analyst Notes:**   Internal TCP/443 connection to 10.10.20.40 completed successfully. Based on the available evidence, this is consistent with expected internal application communication and provides a useful comparison against the unusual external connections.
