<?php
/**
 * InsightGuard AI Compliance Mapper v1.0
 * =======================================
 * Automation Artefact - Component 5
 * Module: 7CS525 Human and Legal Aspects of Cyber Security
 * System Focus: AI-Enabled Insider Threat & Employee Monitoring
 * Organisational Context: UK Government / Public Sector
 *
 * This tool automates AI risk classification under the EU AI Act and
 * maps applicable UK legal and regulatory obligations for insider
 * threat monitoring systems deployed in UK government organisations.
 *
 * Run locally: php -S localhost:8080
 */

session_start();

// ============================================================
// CORE RISK SCORING ENGINE
// ============================================================

function calculateEUAIActRisk(array $capabilities, array $dataTypes, string $automationLevel, array $userGroups): array {
    $score  = 0;
    $reasons = [];

    $capMap = [
        'behavioural_profiling' => [30, 'Behavioural profiling and anomaly scoring of individuals'],
        'emotion_detection'     => [25, 'Emotion / sentiment analysis of employee communications'],
        'biometric'             => [20, 'Biometric data collection or processing'],
        'keylogging'            => [22, 'Keystroke and input monitoring'],
        'email_monitoring'      => [18, 'Interception / analysis of private communications'],
        'file_access'           => [12, 'File access tracking and document exfiltration detection'],
        'web_activity'          => [10, 'Web browsing and internet activity surveillance'],
        'screen_capture'        => [18, 'Periodic screen capture or screen recording'],
        'location_tracking'     => [15, 'Physical or digital location tracking'],
    ];

    foreach ($capMap as $key => [$pts, $label]) {
        if (in_array($key, $capabilities, true)) {
            $score += $pts;
            $reasons[] = $label;
        }
    }

    $autoMap = [
        'full_auto'      => [28, 'Fully automated decisions with no mandatory human review'],
        'high_auto'      => [18, 'High automation — human review only triggered by escalation'],
        'human_in_loop'  => [ 8, 'Human-in-the-loop: analyst reviews all AI-generated alerts'],
        'human_on_loop'  => [14, 'Human-on-the-loop: AI acts, human can intervene'],
    ];

    if (isset($autoMap[$automationLevel])) {
        [$pts, $label] = $autoMap[$automationLevel];
        $score += $pts;
        $reasons[] = $label;
    }

    if (in_array('civil_servants', $userGroups, true)) {
        $score += 12;
        $reasons[] = 'Affects civil servants and public sector workers';
    }
    if (in_array('vulnerable_groups', $userGroups, true)) {
        $score += 20;
        $reasons[] = 'Potentially affects individuals with protected characteristics';
    }
    if (in_array('contractors', $userGroups, true)) {
        $score += 8;
        $reasons[] = 'Extends to third-party contractors';
    }

    if (in_array('special_category', $dataTypes, true)) {
        $score += 22;
        $reasons[] = 'Processes special category personal data (health, religion, trade union, etc.)';
    }
    if (in_array('communications', $dataTypes, true)) {
        $score += 15;
        $reasons[] = 'Captures content of private communications';
    }
    if (in_array('financial', $dataTypes, true)) {
        $score += 10;
        $reasons[] = 'Processes personal financial data';
    }

    return ['score' => min($score, 100), 'reasons' => $reasons];
}

function classifyEURisk(int $score): array {
    if ($score >= 55) {
        return [
            'level'       => 'HIGH RISK',
            'css_class'   => 'risk-high',
            'eu_article'  => 'Annex III, Category 4 — Article 6(2)',
            'colour'      => '#dc2626',
            'summary'     => 'This AI system is classified as HIGH RISK under the EU AI Act. AI systems used in employment contexts for monitoring, ranking, profiling, or making decisions about workers fall squarely within Annex III, Category 4. This triggers a comprehensive set of mandatory obligations prior to, during, and after deployment.',
            'obligations' => [
                'Mandatory conformity assessment before any deployment',
                'Comprehensive technical documentation (Article 11)',
                'Automated logging of all system operations (Article 12)',
                'Mandatory human oversight mechanisms (Article 14)',
                'Transparency obligations towards affected individuals (Article 13)',
                'Data governance and training data quality requirements (Article 10)',
                'Registration in the EU AI Act public database',
                'Post-market monitoring and incident reporting (Article 61)',
                'Risk management system throughout the lifecycle (Article 9)',
            ],
        ];
    } elseif ($score >= 30) {
        return [
            'level'       => 'LIMITED RISK',
            'css_class'   => 'risk-limited',
            'eu_article'  => 'Article 52 — Transparency Obligations',
            'colour'      => '#d97706',
            'summary'     => 'This system falls within the LIMITED RISK category, primarily engaging Article 52 transparency obligations. Individuals interacting with or assessed by the AI system must be clearly informed. While fewer mandatory obligations apply compared to high-risk systems, GDPR and DPA 2018 requirements remain fully applicable.',
            'obligations' => [
                'Inform affected individuals that AI is making or informing decisions',
                'Provide accessible explanations of how decisions are reached',
                'Maintain basic technical documentation',
                'Implement proportionate internal governance policies',
            ],
        ];
    } else {
        return [
            'level'       => 'MINIMAL RISK',
            'css_class'   => 'risk-minimal',
            'eu_article'  => 'Article 69 — Voluntary Codes of Conduct',
            'colour'      => '#16a34a',
            'summary'     => 'This system presents MINIMAL RISK under the EU AI Act. No mandatory AI-specific requirements apply, though voluntary adherence to codes of conduct is encouraged. Standard data protection, employment, and human rights obligations continue to apply.',
            'obligations' => [
                'Voluntary adoption of EU AI Act codes of conduct',
                'Standard GDPR / DPA 2018 compliance obligations',
                'Internal documentation and review recommended',
            ],
        ];
    }
}

function getUKAIPrinciples(array $capabilities, string $automationLevel): array {
    $isHighAuto   = in_array($automationLevel, ['full_auto', 'high_auto'], true);
    $hasBehav     = in_array('behavioural_profiling', $capabilities, true);
    $hasComms     = in_array('email_monitoring', $capabilities, true);

    return [
        [
            'principle'   => 'Safety & Security',
            'regulator'   => 'NCSC / DSIT',
            'status'      => 'ACTION REQUIRED',
            'status_class'=> 'status-action',
            'detail'      => 'DSIT and NCSC expect AI systems processing sensitive government data to undergo rigorous security testing, threat modelling, and adversarial robustness assessments. The monitoring system itself represents a high-value target: compromise of the tool could expose surveillance capabilities and employee data simultaneously. Security by design and regular penetration testing are mandatory expectations.',
        ],
        [
            'principle'   => 'Transparency & Explainability',
            'regulator'   => 'ICO / Cabinet Office',
            'status'      => $hasBehav ? 'HIGH CONCERN' : 'MODERATE CONCERN',
            'status_class'=> $hasBehav ? 'status-high' : 'status-moderate',
            'detail'      => 'The UK AI White Paper requires meaningful explanations of AI-influenced decisions. Where an employee is flagged as a potential insider threat, that determination must be explainable to HR, legal teams, and, ultimately, the employee themselves. Opaque black-box models create accountability gaps that are incompatible with fair employment practice and natural justice principles.',
        ],
        [
            'principle'   => 'Fairness & Non-Discrimination',
            'regulator'   => 'EHRC / ICO',
            'status'      => 'ACTION REQUIRED',
            'status_class'=> 'status-action',
            'detail'      => 'The Equality Act 2010 applies to AI-driven employment decisions. Behavioural analytics trained on historical data risk encoding proxy discrimination — for instance, disproportionately flagging employees who communicate in languages other than English, who observe religious practices affecting working patterns, or who have disabilities affecting their usage patterns. Regular bias disparity audits are essential.',
        ],
        [
            'principle'   => 'Accountability & Governance',
            'regulator'   => 'Cabinet Office / ICO',
            'status'      => 'FRAMEWORK NEEDED',
            'status_class'=> 'status-action',
            'detail'      => 'Clear accountability structures must identify who is responsible at each stage: the AI developer (for the algorithm), the government department (for deployment decisions), and the individual analyst (for acting on alerts). The UK AI White Paper\'s sector-led approach means the ICO, EHRC, and Cabinet Office each apply their existing mandates to this system, creating overlapping accountability obligations.',
        ],
        [
            'principle'   => 'Contestability & Redress',
            'regulator'   => 'ICO / Employment Tribunals',
            'status'      => $isHighAuto ? 'CRITICAL CONCERN' : 'MODERATE CONCERN',
            'status_class'=> $isHighAuto ? 'status-high' : 'status-moderate',
            'detail'      => 'Employees subject to adverse outcomes driven by AI assessments must have accessible, meaningful routes to challenge those outcomes. DPA 2018 rights equivalent to GDPR Article 22 restrict purely automated decisions with significant effects. Employees retain the right to request human review, express their view, and receive an explanation. This must be operationalised, not merely stated in policy.',
        ],
    ];
}

function getLegalFramework(array $capabilities, array $dataTypes): array {
    $hasComms = in_array('email_monitoring', $capabilities, true) || in_array('keylogging', $capabilities, true);
    $hasSpecial = in_array('special_category', $dataTypes, true);

    return [
        [
            'statute'     => 'UK GDPR & Data Protection Act 2018',
            'relevance'   => 'CRITICAL',
            'css'         => 'law-critical',
            'obligations' => 'Lawful basis required for all processing (Art. 6 UK GDPR). Employee monitoring typically relies on legitimate interests — which requires a balancing test. Special category data requires an additional condition under Schedule 1 DPA 2018. A Data Protection Impact Assessment (DPIA) is mandatory under Article 35 for systematic monitoring of employees. Data minimisation, purpose limitation, and storage limitation principles apply. Automated decision-making rights must be operationalised.',
            'risk'        => 'ICO enforcement action; fines up to £17.5 million or 4% of global annual turnover; Enforcement Notices; reputational damage.',
        ],
        [
            'statute'     => 'Regulation of Investigatory Powers Act 2000 (RIPA) & Investigatory Powers Act 2016',
            'relevance'   => $hasComms ? 'CRITICAL' : 'HIGH',
            'css'         => $hasComms ? 'law-critical' : 'law-high',
            'obligations' => 'Monitoring of private communications without lawful authority constitutes unlawful interception under RIPA s.1 / IPA 2016. Employers must have a clear, published monitoring policy; implied consent through awareness of monitoring is accepted but must be genuine. Covert monitoring requires particularly strong justification and, in some cases, formal authorisation under RIPA.',
            'risk'        => 'Criminal liability under RIPA s.1 (unlimited fine or up to 2 years imprisonment); civil claims from affected employees; evidence inadmissibility.',
        ],
        [
            'statute'     => 'Human Rights Act 1998 (Article 8 ECHR — Right to Private Life)',
            'relevance'   => 'CRITICAL',
            'css'         => 'law-critical',
            'obligations' => 'Article 8 rights apply to employees even in the workplace. Any interference must be (a) in accordance with law, (b) pursue a legitimate aim, and (c) be necessary and proportionate. The ECtHR in Bărbulescu v Romania (Grand Chamber, 2017) confirmed that employees retain reasonable privacy expectations at work. The Copland v United Kingdom (2007) judgment confirmed that monitoring internet, email and phone usage engages Article 8.',
            'risk'        => 'Judicial review of government department\'s decision to deploy; successful Article 8 claims; damages awards; Parliamentary scrutiny.',
        ],
        [
            'statute'     => 'Equality Act 2010',
            'relevance'   => 'HIGH',
            'css'         => 'law-high',
            'obligations' => 'The system must not produce outcomes that discriminate — directly or indirectly — on the basis of protected characteristics: age, disability, gender reassignment, marriage/civil partnership, pregnancy/maternity, race, religion/belief, sex, or sexual orientation. Indirect discrimination arises where a facially neutral practice (an AI alert threshold) disadvantages a protected group. Public sector organisations are also subject to the Public Sector Equality Duty (s.149).',
            'risk'        => 'Employment tribunal claims; EHRC formal investigation; s.149 judicial review; significant reputational and financial exposure.',
        ],
        [
            'statute'     => 'Computer Misuse Act 1990',
            'relevance'   => 'MEDIUM',
            'css'         => 'law-medium',
            'obligations' => 'Defines the unauthorised access and computer misuse that the insider threat system is designed to detect. Investigators and security analysts must operate strictly within their own authorised access — they must not use AI-generated alerts as justification to exceed their own access rights when conducting follow-up investigations.',
            'risk'        => 'Criminal prosecution of security analysts who exceed authorised access; civil liability; disciplinary proceedings.',
        ],
        [
            'statute'     => 'Civil Service Code & HMG Security Policy Framework',
            'relevance'   => 'HIGH',
            'css'         => 'law-high',
            'obligations' => 'Government Functional Standard GovS 007 (Security) and the Cabinet Office\'s HMG Security Policy Framework require proportionate, documented personnel security controls. CPNI (Centre for the Protection of National Infrastructure) provides guidance on insider threat programmes. All monitoring must be documented, proportionate, and subject to governance oversight.',
            'risk'        => 'Loss of security accreditation; National Audit Office findings; Cabinet Office intervention; Ministerial accountability.',
        ],
    ];
}

function getRiskMatrix(): array {
    return [
        ['Civil Service Employees',         'Privacy breach & chilling effect on conduct',         'High',   'Critical', 'CRITICAL', 'mat-critical', 'Transparent monitoring policy; DPIA completed; anonymous triage before identity revealed to managers'],
        ['HR & Line Managers',              'Automation bias — over-reliance on AI flags',          'High',   'High',     'CRITICAL', 'mat-critical', 'Mandatory human review requirement; AI decision justified in writing; training on AI limitations'],
        ['Security Operations Analysts',    'Alert fatigue and false-positive overload',            'High',   'High',     'HIGH',     'mat-high',     'Tuned alert thresholds; explainability dashboards; workload limits; model feedback mechanisms'],
        ['Government Department (SIRO)',    'Regulatory sanction and legal non-compliance',         'Medium', 'Critical', 'HIGH',     'mat-high',     'Legal counsel review; ICO pre-consultation; annual compliance audit; DPIA before deployment'],
        ['AI Vendor / Supplier',            'Liability for algorithmic bias or system failure',     'Medium', 'High',     'HIGH',     'mat-high',     'Contractual AI governance clauses; pre-deployment bias testing; technical documentation requirements'],
        ['Employees with Protected Chars.', 'Indirect discrimination and disproportionate flagging','Medium', 'Critical', 'CRITICAL', 'mat-critical', 'Quarterly bias disparity audit; diverse training datasets; EHRC engagement; demographic outcome monitoring'],
        ['Cabinet Office / Ministers',      'Reputational damage and loss of public trust',         'Low',    'Critical', 'HIGH',     'mat-high',     'Transparency framework; Parliamentary scrutiny readiness; proportionality documentation; public interest test'],
        ['Whistleblowers / Trade Unions',   'System used to identify and suppress disclosure',      'Medium', 'Critical', 'HIGH',     'mat-high',     'Explicit legal exclusion of Protected Disclosure activity; trade union consultation; policy safeguards'],
    ];
}

// ============================================================
// FORM PROCESSING
// ============================================================
$submitted = false;
$fd        = [];
$report    = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted = true;

    $fd = [
        'system_name'       => strip_tags(trim($_POST['system_name']    ?? 'InsightGuard Demo System')),
        'org_name'          => strip_tags(trim($_POST['org_name']       ?? 'UK Government Department')),
        'vendor'            => strip_tags(trim($_POST['vendor']         ?? 'Internal Development')),
        'analyst_name'      => strip_tags(trim($_POST['analyst_name']   ?? 'Anonymous')),
        'deployment_year'   => strip_tags(trim($_POST['deployment_year']?? '2025')),
        'employee_count'    => strip_tags(trim($_POST['employee_count'] ?? 'Not specified')),
        'capabilities'      => array_map('strip_tags', (array)($_POST['capabilities']  ?? [])),
        'data_types'        => array_map('strip_tags', (array)($_POST['data_types']    ?? [])),
        'user_groups'       => array_map('strip_tags', (array)($_POST['user_groups']   ?? [])),
        'automation_level'  => strip_tags(trim($_POST['automation_level'] ?? 'human_in_loop')),
        'dpia'              => strip_tags(trim($_POST['dpia']             ?? 'no')),
        'mon_policy'        => strip_tags(trim($_POST['mon_policy']       ?? 'no')),
        'union_consulted'   => strip_tags(trim($_POST['union_consulted']  ?? 'no')),
    ];

    $riskCalc = calculateEUAIActRisk(
        $fd['capabilities'],
        $fd['data_types'],
        $fd['automation_level'],
        $fd['user_groups']
    );

    $report = [
        'score'         => $riskCalc['score'],
        'reasons'       => $riskCalc['reasons'],
        'eu_class'      => classifyEURisk($riskCalc['score']),
        'uk_principles' => getUKAIPrinciples($fd['capabilities'], $fd['automation_level']),
        'legal'         => getLegalFramework($fd['capabilities'], $fd['data_types']),
        'matrix'        => getRiskMatrix(),
        'generated_at'  => date('d F Y \a\t H:i') . ' UTC',
        'report_id'     => 'IGR-' . strtoupper(substr(md5(uniqid('', true)), 0, 8)),
    ];
}

// ============================================================
// HELPER: CAPABILITY / DATA LABELS
// ============================================================
$capLabels = [
    'behavioural_profiling' => 'Behavioural Profiling & Anomaly Scoring',
    'email_monitoring'      => 'Email / Communications Monitoring',
    'keylogging'            => 'Keystroke Logging',
    'file_access'           => 'File Access & Document Tracking',
    'web_activity'          => 'Web Browsing Activity Monitoring',
    'screen_capture'        => 'Screen Capture / Recording',
    'location_tracking'     => 'Location Tracking (Physical / Digital)',
    'biometric'             => 'Biometric Data Processing',
    'emotion_detection'     => 'Emotion / Sentiment Detection',
];
$dataLabels = [
    'behavioural'    => 'Behavioural & Usage Patterns',
    'communications' => 'Communication Content',
    'special_category' => 'Special Category Data (Health, Religion, etc.)',
    'financial'      => 'Financial Data',
    'identity'       => 'Identity & Access Credentials',
    'location'       => 'Location Data',
];
$autoLabels = [
    'full_auto'     => 'Fully Automated — No mandatory human review',
    'high_auto'     => 'High Automation — Escalation triggers human review',
    'human_on_loop' => 'Human-on-the-Loop — AI acts; human can intervene',
    'human_in_loop' => 'Human-in-the-Loop — Analyst reviews every alert',
];
$userLabels = [
    'civil_servants' => 'Civil Servants / Permanent Staff',
    'contractors'    => 'Contractors & Consultants',
    'vulnerable_groups' => 'Individuals with Protected Characteristics',
    'senior_officials' => 'Senior Officials / SCS Grade',
    'security_cleared' => 'Security-Cleared Personnel (SC / DV)',
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>InsightGuard — AI Compliance Mapper v1.0</title>
<style>
  /* ================================================
     GLOBAL RESET & VARIABLES
  ================================================ */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --navy:       #0f2544;
    --navy-mid:   #1a3a5c;
    --teal:       #0d9488;
    --teal-light: #14b8a6;
    --slate:      #475569;
    --light:      #f1f5f9;
    --white:      #ffffff;
    --red:        #dc2626;
    --amber:      #d97706;
    --green:      #16a34a;
    --border:     #cbd5e1;
    --text:       #1e293b;
    --text-muted: #64748b;
    --shadow:     0 4px 20px rgba(0,0,0,0.10);
    --radius:     10px;
  }

  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--light);
    color: var(--text);
    min-height: 100vh;
    font-size: 15px;
    line-height: 1.65;
  }

  /* ================================================
     HEADER
  ================================================ */
  .site-header {
    background: linear-gradient(135deg, var(--navy) 0%, var(--navy-mid) 60%, #1e4d80 100%);
    color: var(--white);
    padding: 28px 0 24px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.25);
  }
  .header-inner {
    max-width: 1080px;
    margin: 0 auto;
    padding: 0 24px;
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .header-logo {
    width: 60px;
    height: 60px;
    background: var(--teal);
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 28px;
    flex-shrink: 0;
  }
  .header-text h1 {
    font-size: 1.75rem;
    font-weight: 700;
    letter-spacing: -0.3px;
  }
  .header-text p {
    font-size: 0.88rem;
    color: rgba(255,255,255,0.72);
    margin-top: 3px;
  }
  .module-tag {
    margin-left: auto;
    background: rgba(255,255,255,0.12);
    border: 1px solid rgba(255,255,255,0.22);
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 0.78rem;
    color: rgba(255,255,255,0.85);
    text-align: right;
    flex-shrink: 0;
  }
  .module-tag strong { display: block; font-size: 0.9rem; color: #fff; }

  /* ================================================
     NAV BREADCRUMB / STEP BAR
  ================================================ */
  .step-bar {
    background: var(--white);
    border-bottom: 1px solid var(--border);
    padding: 12px 0;
  }
  .step-bar-inner {
    max-width: 1080px;
    margin: 0 auto;
    padding: 0 24px;
    display: flex;
    gap: 8px;
    align-items: center;
    font-size: 0.82rem;
    color: var(--text-muted);
  }
  .step-bar-inner span { color: var(--teal); font-weight: 600; }
  .step-bar-inner .sep { color: var(--border); }

  /* ================================================
     MAIN LAYOUT
  ================================================ */
  .container {
    max-width: 1080px;
    margin: 0 auto;
    padding: 36px 24px 60px;
  }

  /* ================================================
     CARDS
  ================================================ */
  .card {
    background: var(--white);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 28px 32px;
    margin-bottom: 24px;
  }
  .card-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--navy);
    margin-bottom: 18px;
    padding-bottom: 12px;
    border-bottom: 2px solid var(--light);
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .card-title .icon {
    width: 32px;
    height: 32px;
    background: var(--teal);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 15px;
    color: #fff;
    flex-shrink: 0;
  }

  /* ================================================
     INTRO PANEL
  ================================================ */
  .intro-panel {
    background: linear-gradient(135deg, var(--navy) 0%, var(--navy-mid) 100%);
    color: var(--white);
    border-radius: var(--radius);
    padding: 32px 36px;
    margin-bottom: 28px;
  }
  .intro-panel h2 { font-size: 1.3rem; margin-bottom: 10px; }
  .intro-panel p  { color: rgba(255,255,255,0.80); font-size: 0.92rem; margin-bottom: 8px; }
  .scope-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 18px;
  }
  .scope-badge {
    background: rgba(13,148,136,0.25);
    border: 1px solid rgba(13,148,136,0.5);
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 0.78rem;
    color: #99f6e4;
  }

  /* ================================================
     FORM STYLES
  ================================================ */
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .form-group { display: flex; flex-direction: column; gap: 6px; }
  .form-group.full { grid-column: 1 / -1; }
  .form-group label {
    font-size: 0.83rem;
    font-weight: 600;
    color: var(--slate);
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }
  .form-group input,
  .form-group select {
    border: 1.5px solid var(--border);
    border-radius: 7px;
    padding: 10px 14px;
    font-size: 0.93rem;
    font-family: inherit;
    color: var(--text);
    background: var(--white);
    transition: border-color 0.2s;
    outline: none;
  }
  .form-group input:focus,
  .form-group select:focus {
    border-color: var(--teal);
    box-shadow: 0 0 0 3px rgba(13,148,136,0.12);
  }

  /* Checkbox groups */
  .checkbox-group {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    margin-top: 4px;
  }
  .check-item {
    display: flex;
    align-items: flex-start;
    gap: 9px;
    padding: 9px 12px;
    border: 1.5px solid var(--border);
    border-radius: 7px;
    cursor: pointer;
    transition: all 0.2s;
    font-size: 0.88rem;
    background: var(--white);
  }
  .check-item:hover { border-color: var(--teal); background: #f0fdfa; }
  .check-item input[type="checkbox"] {
    width: 16px;
    height: 16px;
    flex-shrink: 0;
    margin-top: 2px;
    accent-color: var(--teal);
  }
  .check-item .check-label { font-weight: 500; color: var(--text); line-height: 1.3; }
  .check-item .check-sub   { font-size: 0.76rem; color: var(--text-muted); margin-top: 2px; }

  /* Risk indicator on select */
  .risk-hint {
    font-size: 0.78rem;
    color: var(--text-muted);
    margin-top: 4px;
  }

  /* YNQ row */
  .ynq-row {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }
  .ynq-opt {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 8px 16px;
    border: 1.5px solid var(--border);
    border-radius: 7px;
    cursor: pointer;
    font-size: 0.88rem;
    transition: all 0.2s;
  }
  .ynq-opt:hover { border-color: var(--teal); }
  .ynq-opt input { accent-color: var(--teal); }

  /* Submit */
  .btn-submit {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    background: var(--teal);
    color: var(--white);
    border: none;
    border-radius: 8px;
    padding: 14px 32px;
    font-size: 1rem;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.2s, transform 0.1s;
    margin-top: 10px;
  }
  .btn-submit:hover  { background: #0f766e; }
  .btn-submit:active { transform: scale(0.98); }

  /* ================================================
     REPORT STYLES
  ================================================ */

  /* Report header banner */
  .report-banner {
    background: linear-gradient(135deg, var(--navy) 0%, #1e4d80 100%);
    color: var(--white);
    border-radius: var(--radius);
    padding: 28px 32px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 20px;
  }
  .report-banner h2 { font-size: 1.25rem; margin-bottom: 6px; }
  .report-banner p  { color: rgba(255,255,255,0.70); font-size: 0.86rem; }
  .report-meta {
    text-align: right;
    font-size: 0.80rem;
    color: rgba(255,255,255,0.65);
    flex-shrink: 0;
  }
  .report-meta strong { display: block; font-size: 1rem; color: #fff; margin-bottom: 4px; }

  /* Risk Classification Badge */
  .risk-badge-block {
    border-radius: var(--radius);
    padding: 24px 28px;
    margin-bottom: 20px;
    border-left: 6px solid;
  }
  .risk-high    { background: #fef2f2; border-color: var(--red); }
  .risk-limited { background: #fffbeb; border-color: var(--amber); }
  .risk-minimal { background: #f0fdf4; border-color: var(--green); }

  .risk-level-label {
    font-size: 1.4rem;
    font-weight: 800;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
  }
  .risk-high    .risk-level-label { color: var(--red); }
  .risk-limited .risk-level-label { color: var(--amber); }
  .risk-minimal .risk-level-label { color: var(--green); }

  .risk-article {
    font-size: 0.83rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    margin-bottom: 12px;
  }
  .risk-summary-text { font-size: 0.92rem; line-height: 1.7; }

  /* Score meter */
  .score-block {
    display: flex;
    align-items: center;
    gap: 20px;
    margin: 16px 0;
  }
  .score-circle {
    width: 72px;
    height: 72px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.4rem;
    font-weight: 800;
    color: #fff;
    flex-shrink: 0;
  }
  .sc-high    { background: var(--red); }
  .sc-limited { background: var(--amber); }
  .sc-minimal { background: var(--green); }

  .score-bar-wrap { flex: 1; }
  .score-bar-label { font-size: 0.80rem; color: var(--text-muted); margin-bottom: 5px; }
  .score-bar-track {
    height: 10px;
    background: #e2e8f0;
    border-radius: 99px;
    overflow: hidden;
  }
  .score-bar-fill {
    height: 100%;
    border-radius: 99px;
    transition: width 1s ease;
  }
  .score-markers {
    display: flex;
    justify-content: space-between;
    font-size: 0.72rem;
    color: var(--text-muted);
    margin-top: 3px;
  }

  /* Reason tags */
  .reason-tags { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 14px; }
  .reason-tag {
    background: #fee2e2;
    color: #991b1b;
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 0.78rem;
    font-weight: 500;
  }

  /* Obligations list */
  .obligations-list {
    margin-top: 16px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  .obl-item {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 0.88rem;
    background: rgba(255,255,255,0.7);
    border: 1px solid rgba(0,0,0,0.07);
    border-radius: 7px;
    padding: 8px 11px;
  }
  .obl-item .tick { color: var(--teal); font-size: 1rem; flex-shrink: 0; }

  /* Principles grid */
  .principles-grid { display: grid; gap: 14px; }
  .principle-card {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
    position: relative;
    overflow: hidden;
  }
  .principle-card::before {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 4px;
  }
  .principle-card.status-action::before { background: var(--amber); }
  .principle-card.status-high::before   { background: var(--red); }
  .principle-card.status-moderate::before { background: #3b82f6; }
  .principle-card.status-ok::before     { background: var(--green); }

  .p-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .p-name   { font-weight: 700; font-size: 0.95rem; color: var(--navy); }
  .p-status {
    font-size: 0.73rem;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 20px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }
  .status-action   { background: #fef3c7; color: #92400e; }
  .status-high     { background: #fee2e2; color: #991b1b; }
  .status-moderate { background: #dbeafe; color: #1e40af; }
  .status-ok       { background: #dcfce7; color: #166534; }

  .p-regulator { font-size: 0.76rem; color: var(--text-muted); margin-bottom: 8px; }
  .p-regulator strong { color: var(--teal); }
  .p-detail { font-size: 0.88rem; line-height: 1.65; color: var(--slate); }

  /* Legal framework */
  .law-card {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 14px;
    overflow: hidden;
  }
  .law-header {
    padding: 12px 18px;
    display: flex;
    align-items: center;
    gap: 12px;
    border-bottom: 1px solid var(--border);
  }
  .law-critical .law-header { background: #fef2f2; }
  .law-high     .law-header { background: #fffbeb; }
  .law-medium   .law-header { background: #f0f9ff; }

  .law-relevance-badge {
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.73rem;
    font-weight: 700;
    text-transform: uppercase;
    margin-left: auto;
    flex-shrink: 0;
  }
  .law-critical .law-relevance-badge { background: var(--red);   color: #fff; }
  .law-high     .law-relevance-badge { background: var(--amber); color: #fff; }
  .law-medium   .law-relevance-badge { background: #3b82f6; color: #fff; }

  .law-name { font-weight: 700; font-size: 0.93rem; color: var(--navy); }
  .law-body { padding: 14px 18px; }
  .law-obligations { font-size: 0.88rem; margin-bottom: 10px; line-height: 1.65; }
  .law-risk {
    background: #fff8f8;
    border: 1px solid #fecaca;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 0.82rem;
    color: #7f1d1d;
  }
  .law-risk strong { color: var(--red); }

  /* Risk matrix table */
  .matrix-table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
  .matrix-table th {
    background: var(--navy);
    color: #fff;
    padding: 10px 12px;
    text-align: left;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }
  .matrix-table td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .matrix-table tr:nth-child(even) td { background: #f8fafc; }
  .mat-critical { background: #dc2626 !important; color: #fff !important; font-weight: 700; border-radius: 4px; padding: 3px 8px; }
  .mat-high     { background: #d97706 !important; color: #fff !important; font-weight: 700; border-radius: 4px; padding: 3px 8px; }
  .mat-medium   { background: #3b82f6 !important; color: #fff !important; font-weight: 700; border-radius: 4px; padding: 3px 8px; }

  /* Governance checklist */
  .checklist { list-style: none; display: grid; gap: 8px; }
  .checklist li {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    border-radius: 7px;
    font-size: 0.89rem;
    border: 1px solid;
  }
  .cl-done    { background: #f0fdf4; border-color: #86efac; color: #14532d; }
  .cl-pending { background: #fffbeb; border-color: #fde68a; color: #78350f; }
  .cl-missing { background: #fef2f2; border-color: #fca5a5; color: #7f1d1d; }
  .cl-icon { font-size: 1.1rem; flex-shrink: 0; }

  /* Print */
  .no-print { }
  .print-btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: var(--navy);
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 11px 22px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    margin-left: 12px;
    transition: background 0.2s;
  }
  .print-btn:hover { background: #0f172a; }

  /* Footer */
  .site-footer {
    background: var(--navy);
    color: rgba(255,255,255,0.55);
    text-align: center;
    padding: 18px;
    font-size: 0.78rem;
    margin-top: 40px;
  }
  .site-footer strong { color: rgba(255,255,255,0.85); }

  /* Section heading */
  .section-heading {
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--navy);
    margin: 28px 0 14px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .section-heading .num {
    width: 28px; height: 28px;
    background: var(--teal);
    color: #fff;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.82rem;
    font-weight: 800;
    flex-shrink: 0;
  }

  @media (max-width: 680px) {
    .form-grid, .obligations-list, .checkbox-group { grid-template-columns: 1fr; }
    .report-banner { flex-direction: column; }
  }
  @media print {
    .no-print { display: none !important; }
    body { background: #fff; }
    .card { box-shadow: none; border: 1px solid #ccc; }
  }
</style>
</head>
<body>

<!-- ========== HEADER ========== -->
<header class="site-header">
  <div class="header-inner">
    <div class="header-logo">🔍</div>
    <div class="header-text">
      <h1>InsightGuard AI Compliance Mapper</h1>
      <p>Automated Risk Classification &amp; Regulatory Mapping for AI-Enabled Insider Threat Systems</p>
    </div>
    <div class="module-tag no-print">
      <strong>7CS525</strong>
      Human &amp; Legal Aspects<br>of Cyber Security
    </div>
  </div>
</header>

<div class="step-bar no-print">
  <div class="step-bar-inner">
    <span>InsightGuard v1.0</span>
    <span class="sep">›</span>
    <?php if (!$submitted): ?>
      <span>System Assessment Form</span>
    <?php else: ?>
      System Assessment Form
      <span class="sep">›</span>
      <span>Compliance Report — <?= htmlspecialchars($report['report_id']) ?></span>
    <?php endif; ?>
  </div>
</div>

<!-- ========== MAIN CONTENT ========== -->
<main class="container">

<?php if (!$submitted): ?>
<!-- ======================================================
     FORM VIEW
====================================================== -->
<div class="intro-panel">
  <h2>🛡️ AI Risk &amp; Compliance Assessment Tool</h2>
  <p>Complete the form below to generate a comprehensive compliance report for your AI-enabled insider threat monitoring system. The tool automatically maps your system's characteristics to the <strong>EU AI Act risk classification framework</strong>, the <strong>UK AI White Paper principles</strong>, and all applicable <strong>UK legal obligations</strong>.</p>
  <p>All assessment logic is transparent and auditable. No data is transmitted externally — processing occurs entirely server-side.</p>
  <div class="scope-badges">
    <span class="scope-badge">EU AI Act Annex III</span>
    <span class="scope-badge">UK AI White Paper 2023</span>
    <span class="scope-badge">UK GDPR / DPA 2018</span>
    <span class="scope-badge">RIPA 2000 / IPA 2016</span>
    <span class="scope-badge">Human Rights Act 1998</span>
    <span class="scope-badge">Equality Act 2010</span>
    <span class="scope-badge">HMG Security Policy</span>
  </div>
</div>

<form method="POST" action="">

  <!-- SECTION A: System Identification -->
  <div class="card">
    <div class="card-title"><div class="icon">🏛</div> Section A — System &amp; Organisation Details</div>
    <div class="form-grid">
      <div class="form-group">
        <label>AI System Name / Product Title</label>
        <input type="text" name="system_name" placeholder="e.g. BehaviourSentinel Pro" value="BehaviourSentinel Pro" required>
      </div>
      <div class="form-group">
        <label>Deploying Organisation</label>
        <input type="text" name="org_name" placeholder="e.g. HM Revenue &amp; Customs" value="HM Revenue &amp; Customs" required>
      </div>
      <div class="form-group">
        <label>AI Vendor / Developer</label>
        <input type="text" name="vendor" placeholder="e.g. CyberGuard Systems Ltd" value="CyberGuard Systems Ltd">
      </div>
      <div class="form-group">
        <label>Analyst / Assessor Name</label>
        <input type="text" name="analyst_name" placeholder="Your name or role" value="">
      </div>
      <div class="form-group">
        <label>Year of Deployment</label>
        <input type="text" name="deployment_year" placeholder="e.g. 2025" value="2025">
      </div>
      <div class="form-group">
        <label>Approximate Number of Employees Monitored</label>
        <input type="text" name="employee_count" placeholder="e.g. 4,500" value="4,500">
      </div>
    </div>
  </div>

  <!-- SECTION B: Capabilities -->
  <div class="card">
    <div class="card-title"><div class="icon">⚙️</div> Section B — System Capabilities</div>
    <p style="font-size:0.88rem;color:var(--text-muted);margin-bottom:14px;">Select all capabilities present in the system. Each capability is weighted in the risk scoring engine.</p>
    <div class="checkbox-group">
      <?php foreach ($capLabels as $val => $label): ?>
      <label class="check-item">
        <input type="checkbox" name="capabilities[]" value="<?= $val ?>">
        <div>
          <div class="check-label"><?= htmlspecialchars($label) ?></div>
        </div>
      </label>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- SECTION C: Data Types -->
  <div class="card">
    <div class="card-title"><div class="icon">🗄</div> Section C — Personal Data Processed</div>
    <div class="checkbox-group">
      <?php foreach ($dataLabels as $val => $label): ?>
      <label class="check-item">
        <input type="checkbox" name="data_types[]" value="<?= $val ?>">
        <div>
          <div class="check-label"><?= htmlspecialchars($label) ?></div>
        </div>
      </label>
      <?php endforeach; ?>
    </div>
  </div>

  <!-- SECTION D: Automation & Users -->
  <div class="card">
    <div class="card-title"><div class="icon">🤖</div> Section D — Automation Level &amp; User Groups</div>
    <div class="form-grid">
      <div class="form-group full">
        <label>Level of Human Oversight in Decision-Making</label>
        <select name="automation_level">
          <?php foreach ($autoLabels as $val => $label): ?>
          <option value="<?= $val ?>"><?= htmlspecialchars($label) ?></option>
          <?php endforeach; ?>
        </select>
        <div class="risk-hint">⚠ Higher automation levels substantially increase EU AI Act risk scoring and regulatory obligations.</div>
      </div>
      <div class="form-group full">
        <label>User Groups Affected by the System</label>
        <div class="checkbox-group">
          <?php foreach ($userLabels as $val => $label): ?>
          <label class="check-item">
            <input type="checkbox" name="user_groups[]" value="<?= $val ?>" <?= $val === 'civil_servants' ? 'checked' : '' ?>>
            <div><div class="check-label"><?= htmlspecialchars($label) ?></div></div>
          </label>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
  </div>

  <!-- SECTION E: Governance Status -->
  <div class="card">
    <div class="card-title"><div class="icon">📋</div> Section E — Current Governance Status</div>
    <div class="form-grid">
      <div class="form-group">
        <label>Has a Data Protection Impact Assessment (DPIA) been completed?</label>
        <div class="ynq-row">
          <?php foreach (['yes'=>'Yes — Completed','partial'=>'Partial / In Progress','no'=>'No — Not yet'] as $v=>$l): ?>
          <label class="ynq-opt">
            <input type="radio" name="dpia" value="<?= $v ?>" <?= $v==='no'?'checked':'' ?>>
            <?= $l ?>
          </label>
          <?php endforeach; ?>
        </div>
      </div>
      <div class="form-group">
        <label>Is a published Monitoring Policy in place?</label>
        <div class="ynq-row">
          <?php foreach (['yes'=>'Yes','partial'=>'Draft Only','no'=>'No'] as $v=>$l): ?>
          <label class="ynq-opt">
            <input type="radio" name="mon_policy" value="<?= $v ?>" <?= $v==='no'?'checked':'' ?>>
            <?= $l ?>
          </label>
          <?php endforeach; ?>
        </div>
      </div>
      <div class="form-group full">
        <label>Has trade union / staff representative consultation occurred?</label>
        <div class="ynq-row">
          <?php foreach (['yes'=>'Yes — Consulted','partial'=>'Ongoing','no'=>'No'] as $v=>$l): ?>
          <label class="ynq-opt">
            <input type="radio" name="union_consulted" value="<?= $v ?>" <?= $v==='no'?'checked':'' ?>>
            <?= $l ?>
          </label>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
  </div>

  <div style="display:flex;align-items:center;flex-wrap:wrap;gap:10px;margin-top:8px;">
    <button type="submit" class="btn-submit">
      ⚡ Generate Compliance Report
    </button>
    <p style="font-size:0.80rem;color:var(--text-muted);">Report is generated instantly. No data is stored or transmitted.</p>
  </div>

</form>

<?php else: ?>
<!-- ======================================================
     REPORT VIEW
====================================================== -->

<!-- Report Banner -->
<div class="report-banner">
  <div>
    <h2>🔍 AI Compliance Assessment Report</h2>
    <p><strong style="color:#fff;"><?= htmlspecialchars($fd['system_name']) ?></strong> — <?= htmlspecialchars($fd['org_name']) ?></p>
    <p>Assessed by: <?= htmlspecialchars($fd['analyst_name'] ?: 'Anonymous') ?> &nbsp;|&nbsp; Employees monitored: <?= htmlspecialchars($fd['employee_count']) ?></p>
  </div>
  <div class="report-meta">
    <strong><?= htmlspecialchars($report['report_id']) ?></strong>
    <?= $report['generated_at'] ?><br>
    InsightGuard v1.0<br>
    7CS525 — UoD
  </div>
</div>

<!-- Action buttons -->
<div class="no-print" style="margin-bottom:22px;display:flex;gap:10px;flex-wrap:wrap;">
  <a href="index.php" style="display:inline-flex;align-items:center;gap:8px;background:var(--teal);color:#fff;text-decoration:none;border-radius:8px;padding:11px 22px;font-size:0.9rem;font-weight:600;">
    ← New Assessment
  </a>
  <button class="print-btn" onclick="window.print()">🖨 Print / Save PDF</button>
</div>

<!-- ===== SECTION 1: EU AI ACT RISK CLASSIFICATION ===== -->
<div class="section-heading"><div class="num">1</div> EU AI Act Risk Classification</div>

<?php $cls = $report['eu_class']; ?>
<div class="card <?= $cls['css_class'] ?> risk-badge-block">
  <div class="risk-level-label"><?= $cls['level'] ?></div>
  <div class="risk-article">EU AI Act: <?= $cls['eu_article'] ?></div>

  <div class="score-block">
    <div class="score-circle sc-<?= explode('-',$cls['css_class'])[1] ?>"><?= $report['score'] ?></div>
    <div class="score-bar-wrap">
      <div class="score-bar-label">Risk Score (0–100) — Threshold: 55 = High, 30 = Limited</div>
      <div class="score-bar-track">
        <div class="score-bar-fill" style="width:<?= $report['score'] ?>%;background:<?= $cls['colour'] ?>;"></div>
      </div>
      <div class="score-markers"><span>0 Minimal</span><span>30 Limited</span><span>55 High</span><span>100</span></div>
    </div>
  </div>

  <p class="risk-summary-text"><?= $cls['summary'] ?></p>

  <?php if (!empty($report['reasons'])): ?>
  <div class="reason-tags">
    <?php foreach ($report['reasons'] as $r): ?>
    <span class="reason-tag">⚠ <?= htmlspecialchars($r) ?></span>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>
</div>

<div class="card">
  <div class="card-title"><div class="icon">📜</div> Mandatory Obligations Under This Classification</div>
  <div class="obligations-list">
    <?php foreach ($cls['obligations'] as $obl): ?>
    <div class="obl-item"><span class="tick">✔</span><span><?= htmlspecialchars($obl) ?></span></div>
    <?php endforeach; ?>
  </div>
</div>

<!-- ===== SECTION 2: EU vs UK GOVERNANCE COMPARISON ===== -->
<div class="section-heading"><div class="num">2</div> EU AI Act vs UK AI White Paper — Governance Comparison</div>
<div class="card">
  <div class="card-title"><div class="icon">🌍</div> Regulatory Regime Comparison</div>
  <table class="matrix-table" style="margin-top:6px;">
    <thead>
      <tr>
        <th>Dimension</th>
        <th>EU AI Act (2024)</th>
        <th>UK AI White Paper (2023)</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Regulatory Style</strong></td>
        <td>Binding legislation with mandatory requirements for high-risk systems</td>
        <td>Non-statutory principles-based framework; sector regulators apply existing law</td>
      </tr>
      <tr>
        <td><strong>Risk Classification</strong></td>
        <td>Prescriptive four-tier hierarchy: Unacceptable, High, Limited, Minimal</td>
        <td>No prescribed classification; context-dependent assessment by regulators</td>
      </tr>
      <tr>
        <td><strong>Enforcement Body</strong></td>
        <td>National competent authorities + EU AI Office</td>
        <td>Existing regulators: ICO, EHRC, FCA, CMA — no single AI regulator</td>
      </tr>
      <tr>
        <td><strong>Accountability</strong></td>
        <td>Provider and deployer obligations explicitly defined in law</td>
        <td>Organisations expected to demonstrate accountability voluntarily</td>
      </tr>
      <tr>
        <td><strong>For This System</strong></td>
        <td>Annex III Category 4 — full high-risk obligations triggered</td>
        <td>ICO (data protection), EHRC (equality), Cabinet Office (security policy) all apply</td>
      </tr>
      <tr>
        <td><strong>Applicability to UK Gov</strong></td>
        <td>Applies to UK organisations with EU market exposure post-Brexit</td>
        <td>Directly applicable to UK public sector via government procurement standards</td>
      </tr>
    </tbody>
  </table>
</div>

<!-- ===== SECTION 3: UK AI WHITEPAPER PRINCIPLES ===== -->
<div class="section-heading"><div class="num">3</div> UK AI White Paper — Principles Assessment</div>
<div class="principles-grid">
  <?php foreach ($report['uk_principles'] as $p): ?>
  <div class="principle-card <?= $p['status_class'] ?>">
    <div class="p-header">
      <div class="p-name"><?= htmlspecialchars($p['principle']) ?></div>
      <span class="p-status <?= $p['status_class'] ?>"><?= htmlspecialchars($p['status']) ?></span>
    </div>
    <div class="p-regulator">Responsible Regulator(s): <strong><?= htmlspecialchars($p['regulator']) ?></strong></div>
    <div class="p-detail"><?= htmlspecialchars($p['detail']) ?></div>
  </div>
  <?php endforeach; ?>
</div>

<!-- ===== SECTION 4: LEGAL FRAMEWORK ===== -->
<div class="section-heading"><div class="num">4</div> Applicable UK Legal Framework</div>
<?php foreach ($report['legal'] as $law): ?>
<div class="law-card <?= $law['css'] ?>">
  <div class="law-header">
    <div class="law-name">⚖ <?= htmlspecialchars($law['statute']) ?></div>
    <span class="law-relevance-badge"><?= $law['relevance'] ?></span>
  </div>
  <div class="law-body">
    <div class="law-obligations"><?= htmlspecialchars($law['obligations']) ?></div>
    <div class="law-risk"><strong>⚠ Risk of Non-Compliance:</strong> <?= htmlspecialchars($law['risk']) ?></div>
  </div>
</div>
<?php endforeach; ?>

<!-- ===== SECTION 5: RISK MATRIX ===== -->
<div class="section-heading"><div class="num">5</div> Stakeholder Risk &amp; Compliance Matrix</div>
<div class="card" style="padding:0;overflow:hidden;">
  <div style="overflow-x:auto;">
    <table class="matrix-table">
      <thead>
        <tr>
          <th>Stakeholder</th>
          <th>Risk Identified</th>
          <th>Likelihood</th>
          <th>Impact</th>
          <th>Rating</th>
          <th>Mitigation Strategy</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($report['matrix'] as [$stakeholder,$risk,$likelihood,$impact,$rating,$ratingCss,$mitigation]): ?>
        <tr>
          <td><strong><?= htmlspecialchars($stakeholder) ?></strong></td>
          <td><?= htmlspecialchars($risk) ?></td>
          <td><?= htmlspecialchars($likelihood) ?></td>
          <td><?= htmlspecialchars($impact) ?></td>
          <td><span class="<?= $ratingCss ?>"><?= htmlspecialchars($rating) ?></span></td>
          <td><?= htmlspecialchars($mitigation) ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<!-- ===== SECTION 6: GOVERNANCE CHECKLIST ===== -->
<div class="section-heading"><div class="num">6</div> Governance &amp; Compliance Checklist</div>
<div class="card">
  <div class="card-title"><div class="icon">✅</div> Pre-Deployment &amp; Ongoing Compliance Status</div>
  <ul class="checklist">
    <li class="<?= $fd['dpia']==='yes' ? 'cl-done' : ($fd['dpia']==='partial' ? 'cl-pending' : 'cl-missing') ?>">
      <span class="cl-icon"><?= $fd['dpia']==='yes' ? '✅' : ($fd['dpia']==='partial' ? '⏳' : '❌') ?></span>
      <strong>Data Protection Impact Assessment (DPIA)</strong> — <?= $fd['dpia']==='yes' ? 'Completed' : ($fd['dpia']==='partial' ? 'In progress — must be finalised before deployment' : 'NOT COMPLETED — mandatory under UK GDPR Article 35 for systematic employee monitoring') ?>
    </li>
    <li class="<?= $fd['mon_policy']==='yes' ? 'cl-done' : ($fd['mon_policy']==='partial' ? 'cl-pending' : 'cl-missing') ?>">
      <span class="cl-icon"><?= $fd['mon_policy']==='yes' ? '✅' : ($fd['mon_policy']==='partial' ? '⏳' : '❌') ?></span>
      <strong>Published Employee Monitoring Policy</strong> — <?= $fd['mon_policy']==='yes' ? 'In place' : ($fd['mon_policy']==='partial' ? 'Draft only — must be finalised and communicated to all staff' : 'ABSENT — required to establish informed consent and comply with RIPA / IPA 2016') ?>
    </li>
    <li class="<?= $fd['union_consulted']==='yes' ? 'cl-done' : ($fd['union_consulted']==='partial' ? 'cl-pending' : 'cl-missing') ?>">
      <span class="cl-icon"><?= $fd['union_consulted']==='yes' ? '✅' : ($fd['union_consulted']==='partial' ? '⏳' : '❌') ?></span>
      <strong>Trade Union / Staff Representative Consultation</strong> — <?= $fd['union_consulted']==='yes' ? 'Consultation completed' : ($fd['union_consulted']==='partial' ? 'Ongoing — document outcome and timeline' : 'NOT INITIATED — recommended under good employment practice and ACAS guidance on workplace monitoring') ?>
    </li>
    <li class="cl-pending">
      <span class="cl-icon">⏳</span>
      <strong>EU AI Act Conformity Assessment</strong> — Required if system is classified HIGH RISK. Engage qualified conformity assessment body prior to deployment.
    </li>
    <li class="cl-pending">
      <span class="cl-icon">⏳</span>
      <strong>Algorithmic Bias Audit</strong> — Commission independent disparity analysis across protected characteristic groups before and after deployment (Equality Act 2010, s.149 PSED).
    </li>
    <li class="cl-pending">
      <span class="cl-icon">⏳</span>
      <strong>Human Oversight SOP</strong> — Document the standard operating procedure for analyst review of AI alerts; ensure mandatory human sign-off before any adverse employment action.
    </li>
    <li class="cl-pending">
      <span class="cl-icon">⏳</span>
      <strong>Employee Subject Access Right Procedure</strong> — Establish clear process for employees to exercise SAR rights (UK GDPR Article 15) to access their monitoring data.
    </li>
  </ul>
</div>

<!-- Disclaimer -->
<div class="card" style="background:#fffbeb;border-color:#fde68a;">
  <div style="font-size:0.82rem;color:#78350f;line-height:1.65;">
    <strong>⚠ Disclaimer:</strong> This report is generated by an automated compliance mapping tool for educational and analytical purposes within module 7CS525 at the University of Derby. It does not constitute legal advice. Organisations should seek qualified legal counsel before making deployment decisions. Regulatory obligations may change — verify against the latest EU AI Act recitals and UK ICO guidance at the time of deployment.
  </div>
</div>

<?php endif; ?>
</main>

<footer class="site-footer">
  <strong>InsightGuard AI Compliance Mapper v1.0</strong> — 7CS525 Human &amp; Legal Aspects of Cyber Security &nbsp;|&nbsp;
  University of Derby &nbsp;|&nbsp; Automation Artefact — Component 5 &nbsp;|&nbsp;
  Built with PHP 8+ &nbsp;|&nbsp; <a href="https://github.com" style="color:rgba(255,255,255,0.6);">github.com/[your-username]/insightguard</a>
</footer>

</body>
</html>
