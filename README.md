# InsightGuard AI Compliance Mapper v1.0

**Module:** 7CS525 — Human and Legal Aspects of Cyber Security  
**University of Derby** | Automation Artefact — Component 5

---

## What This Tool Does

InsightGuard is an interactive, server-side PHP application that automates the risk classification and regulatory compliance mapping of AI-enabled **insider threat and employee monitoring systems** deployed in UK Government / Public Sector organisations.

A security analyst or compliance officer completes a structured form describing their system's capabilities, data types, automation level, and governance status. The tool then automatically generates a full compliance report covering:

| Section | Content |
|---------|---------|
| 1 | EU AI Act risk classification with weighted scoring engine |
| 2 | EU AI Act vs UK AI White Paper governance comparison |
| 3 | UK AI White Paper five-principles assessment |
| 4 | Applicable UK legal framework (UK GDPR, RIPA, HRA, Equality Act, etc.) |
| 5 | Stakeholder risk and compliance matrix |
| 6 | Governance checklist with DPIA, monitoring policy, and union consultation status |

---

## Why It Supports Legal, Regulatory & Human-Centred Analysis

The assessment brief (Component 5) requires automation artefacts that **support legal, regulatory, or human-centred cyber security analysis**. This tool:

- **Automates** the EU AI Act risk scoring process, removing manual classification errors
- **Maps** overlapping UK legal obligations that are difficult to track manually
- **Highlights** human-centred risks (automation bias, explainability gaps, discrimination)
- **Produces** a structured, printable governance document suitable for a SIRO or DPO review
- **Demonstrates** the complexity of deploying AI in employment contexts under UK law

---

## How to Run Locally

### Requirements
- PHP 8.0 or higher
- No database or external dependencies required

### Start the Built-in PHP Server

```bash
# Clone the repository
git clone https://github.com/[your-username]/insightguard.git
cd insightguard

# Start the server
php -S localhost:8080

# Open in browser
# http://localhost:8080
```

---

## Project Structure

```
insightguard/
├── index.php       # Complete single-file application (form + report engine)
└── README.md       # This file
```

---

## Academic Context

This artefact was produced as Component 5 of the 7CS525 portfolio assessment. It supports all five assessment components:

- **Component 1** (AI Regulatory & Legal): The EU AI Act risk engine and legal framework section directly operationalise Annex III analysis
- **Component 2** (Human-Centred AI): The principles assessment highlights automation bias, explainability, and contestability risks
- **Component 3** (Risk & Compliance Mapping): The stakeholder matrix and checklist constitute the structured mapping artefact
- **Component 5** (Automation): The PHP application itself is the automation artefact

---

## References

- EU Artificial Intelligence Act (Regulation 2024/1689)
- UK Government AI White Paper (2023) — GOV.UK
- UK GDPR & Data Protection Act 2018
- Regulation of Investigatory Powers Act 2000
- Investigatory Powers Act 2016
- Human Rights Act 1998 / ECHR Article 8
- Equality Act 2010
- HMG Security Policy Framework (Cabinet Office)
