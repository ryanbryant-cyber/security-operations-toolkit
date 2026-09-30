# Windows Memory Forensics Investigation Lab

A hands-on DFIR and memory-forensics project focused on correlating synthetic Windows volatile-memory artifacts to reconstruct suspicious endpoint activity.

The investigation demonstrates how an analyst can combine process relationships, command-line execution, loaded modules, network connections, and memory-region characteristics to identify a high-priority forensic finding without overstating what the available evidence proves.

## Project Objective

Memory analysis can reveal endpoint activity that may not be fully represented in traditional disk, network, or SIEM telemetry.

This project demonstrates how to:

- Reconstruct Windows process relationships
- Analyze suspicious parent-child process behavior
- Review PowerShell command-line activity
- Correlate processes with network connections
- Identify unusual loaded modules
- Evaluate executable memory regions
- Reconstruct an incident timeline
- Score correlated forensic evidence
- Separate confirmed observations from analyst hypotheses
- Generate structured investigation reports
- Validate findings against synthetic ground truth

## Investigation Workflow

```text
Synthetic Memory Evidence
        ↓
Process Enumeration
        ↓
Process Tree Analysis
        ↓
Command-Line Analysis
        ↓
Loaded Module Review
        ↓
Network Correlation
        ↓
Memory Region Analysis
        ↓
Behavioral Correlation
        ↓
Incident Timeline
        ↓
Analyst Assessment
        ↓
Validation
```

## Investigation Scenario

The synthetic investigation centers on:

```text
Host: NFG-FIN-WS07
User: finance.user
```

A Finance user opens a Microsoft Word document from Outlook.

The resulting process activity develops into the following higher-interest chain:

```text
OUTLOOK.EXE
     ↓
WINWORD.EXE
     ↓
powershell.exe
     ├── rundll32.exe
     └── cmd.exe
           ├── whoami.exe
           ├── ipconfig.exe
           └── net.exe
```

Additional forensic artifacts include:

```text
Encoded PowerShell execution
ExecutionPolicy Bypass
Unsigned DLL loaded from Temp
External network communication
Attempted internal SMB communication
Private RWX memory
Private executable memory without backing file
```

No single artifact is treated as definitive proof of compromise.

The investigation priority results from the correlation of multiple independent observations.

# Evidence Sources

The project uses five synthetic forensic datasets.

```text
sample-data/
├── processes.csv
├── command_lines.csv
├── network_connections.csv
├── loaded_modules.csv
└── memory_regions.csv
```

These datasets model artifacts commonly reviewed during Windows memory-forensics investigations.

## Process Evidence

The process dataset contains normal Windows activity alongside the higher-interest chain.

Normal examples include:

```text
System
services.exe
svchost.exe
MsMpEng.exe
explorer.exe
msedge.exe
notepad.exe
```

The suspicious process chain begins with:

```text
outlook.exe
    ↓
winword.exe
    ↓
powershell.exe
```

PowerShell subsequently launches:

```text
rundll32.exe
cmd.exe
```

The command shell then launches:

```text
whoami.exe
ipconfig.exe
net.exe
```

## Command-Line Evidence

PowerShell was observed with:

```text
-NoProfile
-ExecutionPolicy Bypass
-EncodedCommand
```

The encoded value used in the project is intentionally synthetic:

```text
SYNTHETIC_ENCODED_TRAINING_PAYLOAD
```

No real malicious payload is stored or executed.

Discovery commands include:

```text
whoami /all
ipconfig /all
net localgroup administrators
```

These provide evidence of:

- Identity and token discovery
- Network configuration discovery
- Local privileged-group discovery

## Loaded Module Evidence

The most notable module artifact is:

```text
financehelper.dll
```

loaded into:

```text
rundll32.exe
PID 6240
```

from:

```text
C:\Users\finance.user\AppData\Local\Temp\financehelper.dll
```

The module is recorded as:

```text
Unsigned
User-writable Temp location
```

This is higher-interest evidence but does not independently establish that the DLL is malware.

## Network Evidence

The investigation correlates several network events.

### rundll32.exe

```text
203.0.113.88:8443
State: ESTABLISHED
```

### powershell.exe

```text
203.0.113.77:443
State: ESTABLISHED
```

### cmd.exe

```text
10.10.20.40:445
State: SYN_SENT
```

The SMB event is intentionally classified as:

```text
Attempted internal SMB communication
```

rather than successful lateral movement because the available evidence only shows `SYN_SENT`.

## Memory Region Evidence

The strongest memory-region artifact appears in:

```text
rundll32.exe
PID 6240
```

One region contains:

```text
Protection:     RWX
Private Memory: True
Executable:     True
Writable:       True
Backing File:   None
```

Another contains:

```text
Protection:     RX
Private Memory: True
Executable:     True
Backing File:   None
```

Private executable memory, especially writable-and-executable memory, warrants investigation.

However, this evidence does not independently prove process injection.

# Correlated Investigation Timeline

The reconstructed timeline includes:

```text
13:11:48
WINWORD.EXE starts
        ↓
13:12:19
PowerShell launches
-NoProfile
-ExecutionPolicy Bypass
-EncodedCommand
        ↓
13:12:36
rundll32.exe launches
        ↓
13:12:38
Unsigned financehelper.dll loads from Temp
        ↓
13:12:40
Private RWX memory observed
        ↓
13:12:41
Private RX memory without backing file observed
        ↓
13:12:44
rundll32.exe → 203.0.113.88:8443
        ↓
13:13:04
cmd.exe launches
        ↓
13:13:18
PowerShell → 203.0.113.77:443
        ↓
13:13:31
whoami /all
        ↓
13:13:52
Attempted SMB → 10.10.20.40:445
        ↓
13:14:12
ipconfig /all
        ↓
13:14:47
net localgroup administrators
```

# Behavioral Analysis Model

Detection logic is stored in:

```text
rules/
└── forensic_rules.json
```

The scoring model uses correlated evidence rather than a single artifact.

## Process Relationships

```text
Office → PowerShell            +15
PowerShell → rundll32          +15
PowerShell → cmd                +8
```

## Command-Line Indicators

```text
Encoded PowerShell             +15
ExecutionPolicy Bypass         +10
-NoProfile                      +3
Multiple discovery commands    +10
```

## Module Indicators

```text
Unsigned module                +10
User-writable module path      +10
Unsigned DLL from Temp         +15
```

## Network Indicators

```text
rundll32 external connection   +15
PowerShell external connection +10
Higher-interest port            +5
Attempted internal SMB          +5
```

## Memory Indicators

```text
Private RWX memory             +20
Private executable unbacked    +10
```

The final score is capped at:

```text
100
```

This score represents **investigation priority within this custom educational model**, not a percentage probability that malicious activity occurred.

# Analysis Results

Running:

```bash
python3 analyze_memory.py
```

produced:

```text
Finding:    MEM-INV-001
Host:       NFG-FIN-WS07
User:       finance.user
Score:      100
Priority:   HIGH
Indicators: 16
```

The analyzer identified all 16 configured forensic indicators:

```text
Office process spawned PowerShell
PowerShell spawned rundll32
PowerShell spawned command shell
Encoded PowerShell command
PowerShell execution policy bypass
PowerShell launched without profile
Multiple discovery commands
Unsigned module loaded
Module loaded from user-writable path
Unsigned DLL loaded from Temp
External connection from rundll32
External connection from PowerShell
Higher-interest destination port
Attempted internal SMB communication
Private RWX memory
Private executable memory without backing file
```

# Analyst Assessment

The correlated evidence supports a **high-priority investigation**.

Multiple independent forensic artifacts converge on the same process chain involving:

- Microsoft Word
- PowerShell
- rundll32.exe
- Discovery commands
- An unsigned DLL
- A user-writable Temp directory
- External network communication
- Private executable memory

However, the available evidence does **not independently prove**:

```text
Malware
Command-and-control
Process injection
Successful lateral movement
```

Further analysis would be required before making those conclusions.

# Evidentiary Guardrails

The project deliberately includes analyst guardrails.

```text
Do not classify an unsigned DLL as malware
without additional analysis.
```

```text
Do not classify private executable memory
as confirmed process injection without
evidence establishing the injection mechanism.
```

```text
Do not classify an outbound connection as
command-and-control solely because the
destination or port is unusual.
```

```text
Do not classify a SYN_SENT SMB event as
successful lateral movement.
```

These guardrails reinforce a core DFIR principle:

> Report what the evidence establishes, and clearly separate observations from hypotheses.

# Generated Reports

The analysis engine produces:

```text
output/
├── memory_forensics_results.json
└── memory_forensics_findings.csv
```

The JSON report preserves:

- Finding metadata
- Risk score
- Investigation priority
- Indicator details
- Evidence supporting each indicator
- Process chain
- Reconstructed timeline
- Analyst assessment
- Evidentiary guardrails

The CSV output provides a concise analyst-facing summary.

# Validation

The project includes an independent validator:

```text
validate_findings.py
```

Expected findings are stored in:

```text
expected-results/
└── memory_forensics_expectations.json
```

The validator checks more than whether the script successfully runs.

It verifies:

- Finding count
- Host and user identity
- Risk score
- Investigation priority
- Exact indicator count
- All 16 required forensic indicators
- Process-chain reconstruction
- Timeline evidence
- Unsigned Temp DLL evidence
- Private executable memory evidence
- SMB classification precision
- Analyst guardrails
- Evidentiary uncertainty

# Validation Results

The completed validation produced:

```text
PASS    Finding summary
PASS    Primary memory-forensics finding
PASS    All required forensic indicators are present
PASS    Suspicious process chain is reconstructed correctly
PASS    Timeline contains required correlated forensic evidence
PASS    Unsigned Temp DLL evidence is preserved
PASS    Private executable memory evidence is detected
PASS    SMB activity remains classified as attempted communication
PASS    Forensic analyst guardrails are present
PASS    Analyst assessment preserves evidentiary uncertainty
```

Final result:

```text
Checks run:     10
Checks passed:  10
Checks failed:  0
Overall:        PASS
```

The generated validation report is stored in:

```text
output/
└── memory_forensics_validation_results.json
```

# Project Structure

```text
windows-memory-forensics-lab/
├── README.md
├── analyze_memory.py
├── validate_findings.py
├── sample-data/
│   ├── processes.csv
│   ├── command_lines.csv
│   ├── network_connections.csv
│   ├── loaded_modules.csv
│   └── memory_regions.csv
├── rules/
│   └── forensic_rules.json
├── expected-results/
│   └── memory_forensics_expectations.json
└── output/
    ├── memory_forensics_results.json
    ├── memory_forensics_findings.csv
    └── memory_forensics_validation_results.json
```

# Skills Demonstrated

```text
Memory Forensics
Digital Forensics
DFIR
Windows Process Analysis
Process Tree Analysis
Command-Line Analysis
PowerShell Investigation
Loaded Module Analysis
Memory Region Analysis
Network Connection Analysis
Malware Triage
Behavioral Correlation
Incident Reconstruction
Evidence Analysis
Forensic Timeline Development
Risk-Based Investigation
Python
CSV Processing
JSON Processing
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## A process name alone does not establish malicious behavior

Utilities such as:

```text
powershell.exe
rundll32.exe
cmd.exe
```

are legitimate Windows components.

The surrounding context determines investigative significance.

## Parent-child relationships provide important context

```text
WINWORD.EXE
    ↓
powershell.exe
```

is more noteworthy than PowerShell simply existing in memory.

Adding:

```text
powershell.exe
    ↓
rundll32.exe
```

further increases investigative interest.

## Correlation strengthens conclusions

No individual artifact in this project independently confirms malicious activity.

Confidence rises because multiple independent evidence sources converge on the same process chain.

## Private executable memory requires careful interpretation

RWX or unbacked executable memory can be associated with suspicious in-memory behavior.

It can also exist for legitimate reasons.

The artifact should trigger investigation rather than automatic attribution.

## Network state matters

```text
SYN_SENT
```

does not establish a completed network session.

This distinction prevents an attempted SMB connection from being incorrectly reported as successful lateral movement.

## Forensic reports should preserve uncertainty

A strong forensic report clearly distinguishes:

```text
Observed Evidence
```

from:

```text
Analyst Hypothesis
```

This makes findings more defensible and useful to incident responders.

# Limitations

This project uses synthetic forensic artifacts rather than an actual memory image.

The datasets are designed to model evidence an analyst might review using memory-forensics tools.

The project does not:

- Execute malware
- Analyze a live compromised host
- Capture credentials
- Inject processes
- Dump production memory
- Perform live C2 communication
- Confirm malware families
- Prove an injection technique

Future improvements could include:

- Volatility 3 analysis
- Real training memory-image ingestion
- `windows.pslist`
- `windows.pstree`
- `windows.cmdline`
- `windows.netscan`
- `windows.dlllist`
- `windows.malfind`
- Process-token analysis
- Handle analysis
- PE metadata extraction
- YARA scanning of memory regions
- Timeline normalization
- Threat-intelligence enrichment
- MITRE ATT&CK mapping
- Automated DFIR case reporting

# Safety

All hosts, users, processes, commands, IP addresses, files, modules, and memory artifacts used in this project are synthetic or reserved for documentation and testing.

No live malware or production systems were used.

The project is limited to defensive forensic analysis, correlation, reporting, and validation.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- analyzes five synthetic forensic evidence sources
- reconstructs a suspicious Windows process chain
- evaluates PowerShell command-line behavior
- identifies discovery activity
- detects an unsigned Temp DLL
- correlates outbound network communication
- identifies attempted SMB activity
- identifies private RWX memory
- identifies unbacked executable memory
- correlates 16 forensic indicators
- assigns HIGH investigation priority
- reconstructs an incident timeline
- preserves evidentiary uncertainty
- exports CSV and JSON findings
- validates every expected result
- passes 10 of 10 validation checks
