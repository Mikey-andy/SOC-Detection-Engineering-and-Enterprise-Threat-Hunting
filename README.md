# SOC Detection Engineering & Threat Hunting Portfolio

Hey there! Welcome to my detection engineering repository. 

I'm building this repository to document my journey toward mastering enterprise security, SIEM architecture, and detection engineering. Instead of just reading theory, my focus here is on building production-grade, high-performance detection rules from the ground up—focusing on raw Windows telemetry, proper log normalization, and reducing false positives.

Every detection rule in this portfolio is built with real-world enterprise constraints in mind, aligning with standard threat frameworks (like MITRE ATT&CK) and strict regulatory baselines.

---

## 📂 Repository Structure

```text
.
├── README.md
└── Detections
    ├── Windows
    │   ├── Auth_Brute_Force_Detection.md        <-- Tracking authentication failures & brute-force
    │   └── Persistence_Process_Execution.md     <-- Spotting web shell execution & scheduled tasks
    └── Network
        └── Outbound_C2_Detection.md             <-- Catching suspicious outbound beaconing
