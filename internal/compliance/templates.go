package compliance

// Regime templates. Versions are dated; add a new version (never edit a released one) when a
// mapping changes, so a report always names the exact mapping it was produced with.

const commonDisclaimer = "This pack maps evidence held in Ledger to the cited requirements to assist an assessor. " +
	"A 'pass' means only that the stated evidence criterion is met by verifiable ledger records; it is not legal advice " +
	"and does not by itself establish conformity or compliance. 'manual' controls require evidence Ledger does not hold."

func integrityControls(prefix string) []Control {
	return []Control{
		{ID: prefix + "-INT-1", Citation: "Integrity", Title: "Hash-chain verification",
			Requirement:   "Logs are protected against undetected alteration or deletion.",
			EvidenceQuery: "Re-verify every chain in scope from seq 1: seq continuity, prev_hash linkage, recomputed record hashes, chain head pointer.",
			Eval:          integrityFinding},
		{ID: prefix + "-INT-2", Citation: "Integrity", Title: "External anchors",
			Requirement:   "Tamper-evidence does not depend on trusting the database operator.",
			EvidenceQuery: "Re-verify every stored anchor receipt (RFC 3161 tokens, git commits, signed roots) offline and prove each anchored (seq, head) is still a prefix of the chain.",
			Eval:          anchorFinding},
		{ID: prefix + "-INT-3", Citation: "Integrity", Title: "Root-key rotation history",
			Requirement:   "Signing keys are managed and their succession is provable.",
			EvidenceQuery: "ledger.key.rotated records in the `ledger` system chain; both signatures of each rotation statement verify and chain from a trusted key.",
			Eval:          keyRotationFinding},
	}
}

func init() {
	Register(euAIAct())
	Register(soc2())
	Register(hipaa())
}

func euAIAct() Template {
	return Template{
		Regime: "eu-ai-act", Version: "2026.09", Title: "EU AI Act — record-keeping, oversight and monitoring evidence",
		Source:     "Regulation (EU) 2024/1689 (Artificial Intelligence Act), Articles 12, 14, 19, 26, 72, 73",
		Disclaimer: commonDisclaimer,
		Sections: []Section{
			{Title: "Article 12 — Record-keeping", Controls: []Control{
				{ID: "AIA-12.1", Citation: "Art. 12(1)", Title: "Automatic recording of events",
					Requirement:   "High-risk AI systems technically allow for the automatic recording of events (logs) over the lifetime of the system.",
					EvidenceQuery: "Records in scope written by the emitting systems via the Ledger API/SDK, in chains that verify intact.",
					Eval:          loggingFinding},
				{ID: "AIA-12.2a", Citation: "Art. 12(2)(a)", Title: "Identifying risk situations and substantial modifications",
					Requirement:   "Logging enables identifying situations that may result in a risk or a substantial modification.",
					EvidenceQuery: "Records with a risk score, failed check, block decision, denial or incident; policy versions attached to decisions.",
					Eval: func(ev *Evidence) Finding {
						f := riskSignalsFinding(ev)
						pv := policyVersionFinding(ev)
						if pv.Status == Gap && f.Status != Gap {
							f.Status, f.Summary = Gap, f.Summary+" "+pv.Summary
						} else {
							f.Summary += " " + pv.Summary
						}
						return f
					}},
				{ID: "AIA-12.2b", Citation: "Art. 12(2)(b)", Title: "Facilitating post-market monitoring",
					Requirement:   "Logging facilitates the post-market monitoring referred to in Article 72.",
					EvidenceQuery: "Records linked to goals so that each task can be replayed in order.",
					Eval:          replayabilityFinding},
				{ID: "AIA-12.2c", Citation: "Art. 12(2)(c)", Title: "Monitoring the operation (Art. 26(5))",
					Requirement:   "Logging enables monitoring the operation of the system by deployers.",
					EvidenceQuery: "Every agent actor carries a model and model_version identifier.",
					Eval:          agentIdentityFinding},
			}},
			{Title: "Article 14 — Human oversight", Controls: []Control{
				{ID: "AIA-14.1", Citation: "Art. 14(1)", Title: "Oversight by natural persons",
					Requirement:   "Systems are designed so that they can be effectively overseen by natural persons.",
					EvidenceQuery: "Every record's actor_chain starts with an originating human (enforced at append time; re-checked here).",
					Eval:          humanOriginFinding},
				{ID: "AIA-14.4de", Citation: "Art. 14(4)(d)-(e)", Title: "Decide not to use, override, interrupt",
					Requirement:   "Overseers can disregard, override or reverse output and intervene or interrupt the system.",
					EvidenceQuery: "Approval, denial, revocation, halt, gate-decision and state-transition records.",
					Eval:          oversightFinding},
				{ID: "AIA-14.5", Citation: "Art. 14(5)", Title: "Two-person verification (where required)",
					Requirement:   "For Annex III point 1(a) systems, identification results are verified by at least two natural persons.",
					EvidenceQuery: "Approval decisions whose deciding human differs from the requesting human (by request_id).",
					Eval:          dualControlFinding},
			}},
			{Title: "Article 19 — Automatically generated logs (providers)", Controls: []Control{
				{ID: "AIA-19.1", Citation: "Art. 19(1)", Title: "Log retention of at least six months",
					Requirement:   "Providers keep automatically generated logs for a period appropriate to the intended purpose, of at least six months.",
					EvidenceQuery: "A recorded retention policy (ledger.retention.policy.set) of >= 6 months on every chain in scope; expiry never deletes.",
					Eval:          func(ev *Evidence) Finding { return retentionFinding(ev, "EU AI Act Art. 19", "6m") }},
			}},
			{Title: "Article 26 — Obligations of deployers", Controls: []Control{
				{ID: "AIA-26.1", Citation: "Art. 26(1)", Title: "Use in accordance with instructions for use",
					Requirement:   "Deployers take technical and organisational measures to use systems per the instructions for use.",
					EvidenceQuery: "Not derivable from logs.",
					Eval:          manual("Requires the deployer's operating procedures and the provider's instructions for use.")},
				{ID: "AIA-26.2", Citation: "Art. 26(2)", Title: "Oversight assigned to competent persons",
					Requirement:   "Human oversight is assigned to natural persons with the necessary competence, training and authority.",
					EvidenceQuery: "Identities of the humans recorded on oversight records (competence itself is not in the ledger).",
					Eval: func(ev *Evidence) Finding {
						f := oversightFinding(ev)
						f.Status = Manual
						f.Summary = "Oversight actions are attributed to named persons (see evidence); their competence, training and authority must be evidenced from HR/training records. " + f.Summary
						return f
					}},
				{ID: "AIA-26.5", Citation: "Art. 26(5)", Title: "Monitoring operation; suspension on risk",
					Requirement:   "Deployers monitor operation and, on risk or serious incident, inform the provider and suspend use.",
					EvidenceQuery: "Chains externally anchored and re-verified; risk events and interventions recorded.",
					Eval: func(ev *Evidence) Finding {
						a := anchorFinding(ev)
						o := oversightFinding(ev)
						if a.Status == Pass && o.Status == Pass {
							return Finding{Status: Pass, Summary: a.Summary + " " + o.Summary, Count: o.Count, Evidence: o.Evidence, Metrics: a.Metrics}
						}
						return Finding{Status: Gap, Summary: a.Summary + " " + o.Summary, Count: o.Count, Evidence: o.Evidence, Metrics: a.Metrics}
					}},
				{ID: "AIA-26.6", Citation: "Art. 26(6)", Title: "Deployer log retention of at least six months",
					Requirement:   "Deployers keep the logs under their control for at least six months.",
					EvidenceQuery: "Retention policy >= 6 months on every chain in scope.",
					Eval:          func(ev *Evidence) Finding { return retentionFinding(ev, "EU AI Act Art. 26(6)", "6m") }},
			}},
			{Title: "Articles 72-73 — Post-market monitoring and serious incidents", Controls: []Control{
				{ID: "AIA-72", Citation: "Art. 72(1)-(2)", Title: "Post-market monitoring data collection",
					Requirement:   "The post-market monitoring system actively and systematically collects, documents and analyses performance data.",
					EvidenceQuery: "Tamper-evident, replayable records for the period (Art. 12 evidence); the monitoring plan itself is documentation outside Ledger.",
					Eval: func(ev *Evidence) Finding {
						l := loggingFinding(ev)
						r := replayabilityFinding(ev)
						st := Pass
						if l.Status != Pass || r.Status != Pass {
							st = Gap
						}
						return Finding{Status: st, Summary: l.Summary + " " + r.Summary + " The post-market monitoring plan (Art. 72(3)) must be provided separately.", Metrics: l.Metrics}
					}},
				{ID: "AIA-73", Citation: "Art. 73(2)-(4)", Title: "Serious-incident reporting hook",
					Requirement:   "Serious incidents are reported to market surveillance authorities within 15 days (2 days: widespread / critical infrastructure; 10 days: death).",
					EvidenceQuery: "Every ledger.incident.serious (or severity=serious incident) record has a *.incident.reported record with the same incident_id within its deadline.",
					Eval:          incidentReportingFinding},
			}},
			{Title: "Integrity and provenance of this evidence", Controls: integrityControls("AIA")},
		},
	}
}

func soc2() Template {
	return Template{
		Regime: "soc2", Version: "2026.09", Title: "SOC 2 — logical access, system operations and change management evidence",
		Source:     "AICPA Trust Services Criteria (2017, revised points of focus 2022): CC6, CC7, CC8",
		Disclaimer: commonDisclaimer,
		Sections: []Section{
			{Title: "CC6 — Logical and physical access controls", Controls: []Control{
				{ID: "CC6.1", Citation: "CC6.1", Title: "Logical access security over protected assets",
					Requirement:   "The entity implements logical access security software, infrastructure and architectures over protected information assets.",
					EvidenceQuery: "warrant.token.issued records: scoped capability tokens for agents, each attributed to an originating human.",
					Eval:          tokenIssuanceFinding},
				{ID: "CC6.1-KM", Citation: "CC6.1 (key management)", Title: "Protection of signing keys",
					Requirement:   "Encryption/signing keys are managed through their lifecycle.",
					EvidenceQuery: "Cross-signed root-key rotations in the ledger system chain.",
					Eval:          keyRotationFinding},
				{ID: "CC6.2", Citation: "CC6.2", Title: "Authorisation before access is granted",
					Requirement:   "Users are registered and authorised before credentials are issued.",
					EvidenceQuery: "All records (including token issuance) begin with an originating human; no anonymous actions.",
					Eval:          humanOriginFinding},
				{ID: "CC6.3", Citation: "CC6.3", Title: "Access modification and removal",
					Requirement:   "Access is authorised, modified or removed based on roles and least privilege.",
					EvidenceQuery: "warrant.token.revoked records and tokens bounded by expiry or call limits.",
					Eval:          revocationFinding},
				{ID: "CC6.8", Citation: "CC6.6 / CC6.8", Title: "Enforcement against unauthorised actions",
					Requirement:   "The entity restricts and detects unauthorised actions.",
					EvidenceQuery: "warrant.call.allowed / warrant.call.denied decisions.",
					Eval:          enforcementFinding},
			}},
			{Title: "CC7 — System operations", Controls: []Control{
				{ID: "CC7.1", Citation: "CC7.1", Title: "Detection of configuration changes",
					Requirement:   "Detection and monitoring procedures identify configuration changes.",
					EvidenceQuery: "policy_version on decisions and *.policy.version.created records.",
					Eval:          policyVersionFinding},
				{ID: "CC7.2", Citation: "CC7.2", Title: "Monitoring of system components for anomalies",
					Requirement:   "System components are monitored for anomalies indicative of malicious acts or errors.",
					EvidenceQuery: "External anchors re-verified; hash chains verified (log tampering would be detected).",
					Eval: func(ev *Evidence) Finding {
						a, i := anchorFinding(ev), integrityFinding(ev)
						st := Pass
						if a.Status != Pass || i.Status != Pass {
							st = Gap
						}
						return Finding{Status: st, Summary: i.Summary + " " + a.Summary, Metrics: a.Metrics}
					}},
				{ID: "CC7.3", Citation: "CC7.3", Title: "Evaluation of security events",
					Requirement:   "Security events are evaluated to determine whether they are incidents.",
					EvidenceQuery: "Risk-relevant events: failed checks, blocks, denials, incidents.",
					Eval:          riskSignalsFinding},
				{ID: "CC7.4", Citation: "CC7.4", Title: "Incident response",
					Requirement:   "Identified incidents are responded to (contain, remediate, communicate).",
					EvidenceQuery: "Incident records (payload incident_id) each followed by a *.incident.resolved record.",
					Eval:          incidentResponseFinding},
				{ID: "CC7.5", Citation: "CC7.5", Title: "Recovery",
					Requirement:   "The entity identifies, develops and implements activities to recover from incidents.",
					EvidenceQuery: "ledger.backup.created records from signed, verifiable `ledger backup` runs.",
					Eval:          backupFinding},
			}},
			{Title: "CC8 — Change management", Controls: []Control{
				{ID: "CC8.1", Citation: "CC8.1", Title: "Changes authorised, tested and approved",
					Requirement:   "Changes to infrastructure, data and software are authorised, designed, tested, approved and implemented.",
					EvidenceQuery: "Every gate.run.started has a gate.run.decided/enforced; human approval decisions.",
					Eval:          changeMgmtFinding},
			}},
			{Title: "Integrity and provenance of this evidence", Controls: integrityControls("SOC2")},
		},
	}
}

func hipaa() Template {
	return Template{
		Regime: "hipaa", Version: "2026.09", Title: "HIPAA Security Rule — technical safeguards and documentation evidence",
		Source:     "45 CFR Part 164 Subpart C: 164.308, 164.312, 164.316",
		Disclaimer: commonDisclaimer,
		Sections: []Section{
			{Title: "164.312 — Technical safeguards", Controls: []Control{
				{ID: "164.312(b)", Citation: "45 CFR 164.312(b)", Title: "Audit controls",
					Requirement:   "Implement mechanisms that record and examine activity in information systems that contain or use ePHI.",
					EvidenceQuery: "Records in scope in verified chains; replayable per goal.",
					Eval:          loggingFinding},
				{ID: "164.312(c)(1)", Citation: "45 CFR 164.312(c)(1)", Title: "Integrity",
					Requirement:   "Protect ePHI from improper alteration or destruction.",
					EvidenceQuery: "Append-only chains re-verified end to end.",
					Eval:          integrityFinding},
				{ID: "164.312(c)(2)", Citation: "45 CFR 164.312(c)(2) (addressable)", Title: "Mechanism to authenticate ePHI",
					Requirement:   "Electronic mechanisms corroborate that ePHI has not been altered or destroyed in an unauthorized manner.",
					EvidenceQuery: "Signed roots and third-party anchor receipts re-verified; anchored heads still on the chain.",
					Eval:          anchorFinding},
				{ID: "164.312(d)", Citation: "45 CFR 164.312(d)", Title: "Person or entity authentication",
					Requirement:   "Verify that a person or entity seeking access to ePHI is the one claimed.",
					EvidenceQuery: "Every action attributed to an originating human; agent access via Warrant capability tokens.",
					Eval: func(ev *Evidence) Finding {
						h := humanOriginFinding(ev)
						tk := tokenIssuanceFinding(ev)
						agents := false
						for _, r := range ev.Records {
							if len(actors(r)) > 1 {
								agents = true
								break
							}
						}
						if h.Status != Pass || (agents && tk.Status != Pass) {
							s := h.Summary
							if agents && tk.Status != Pass {
								s += " Agents acted but " + tk.Summary
							}
							return Finding{Status: Gap, Summary: s, Metrics: h.Metrics}
						}
						return Finding{Status: Pass, Summary: h.Summary + " " + tk.Summary + " (Authentication of the human at login is outside Ledger.)", Count: tk.Count, Evidence: tk.Evidence, Metrics: h.Metrics}
					}},
				{ID: "164.312(a)(2)(iv)", Citation: "45 CFR 164.312(a)(2)(iv) (addressable)", Title: "Encryption and decryption",
					Requirement:   "Implement a mechanism to encrypt and decrypt ePHI.",
					EvidenceQuery: "Payloads stored as per-subject AES-256-GCM envelopes (ledger-envelope/v1).",
					Eval:          encryptionFinding},
			}},
			{Title: "164.308 — Administrative safeguards", Controls: []Control{
				{ID: "164.308(a)(1)(ii)(D)", Citation: "45 CFR 164.308(a)(1)(ii)(D)", Title: "Information system activity review",
					Requirement:   "Regularly review records of information system activity (audit logs, access and incident reports).",
					EvidenceQuery: "Access decisions and oversight actions recorded; the review cadence itself is organisational.",
					Eval: func(ev *Evidence) Finding {
						f := oversightFinding(ev)
						if f.Status == Pass {
							f.Status = Manual
							f.Summary = "Reviewable activity exists (" + f.Summary + ") — evidence that it was regularly reviewed must be provided separately."
						}
						return f
					}},
				{ID: "164.308(a)(7)(ii)(A)", Citation: "45 CFR 164.308(a)(7)(ii)(A)", Title: "Data backup plan",
					Requirement:   "Establish procedures to create and maintain retrievable exact copies of ePHI.",
					EvidenceQuery: "ledger.backup.created records from signed, verifiable backups.",
					Eval:          backupFinding},
			}},
			{Title: "164.316 — Policies, procedures and documentation", Controls: []Control{
				{ID: "164.316(b)(2)(i)", Citation: "45 CFR 164.316(b)(2)(i)", Title: "Retention of six years",
					Requirement:   "Retain required documentation for 6 years from creation or last effective date.",
					EvidenceQuery: "Retention policy >= 6y (regime hipaa) on every chain in scope; records append-only; erasures only shred payloads and are recorded.",
					Eval:          func(ev *Evidence) Finding { return retentionFinding(ev, "HIPAA 164.316(b)(2)(i)", "6y") }},
				{ID: "164.316(b)(1)", Citation: "45 CFR 164.316(b)(1)", Title: "Documentation of policies and procedures",
					Requirement:   "Maintain written policies and procedures and records of required actions.",
					EvidenceQuery: "Not derivable from logs (retention policies and legal holds recorded in Ledger are listed in the appendix).",
					Eval:          manual("Written security policies and procedures must be provided by the covered entity; Ledger lists the retention policies and legal holds it records.")},
			}},
			{Title: "Integrity and provenance of this evidence", Controls: integrityControls("HIPAA")},
		},
	}
}
