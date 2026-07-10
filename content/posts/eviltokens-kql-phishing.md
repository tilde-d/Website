+++
title = "How a Single KQL Query Stopped an Entire EvilTokens Phishing Campaign"
date = 2026-06-11T21:29:58-06:00
draft = false
summary = "An AI-powered PhaaS campaign leaned on legit-vendor redirects and device-code phishing — but spoofing left a fingerprint. One KQL query plus a 5-minute MDE automation loop neutralized over 1,200 malicious emails in 48 hours."
tags = ["kql", "phishing", "detection-engineering", "sentinel", "defender"]
canonicalURL = "https://medium.com/@mattcswann/how-a-single-kql-query-stopped-an-entire-eviltokens-phishing-campaign-9b9dd4e32920"
+++

Back in April of this year, an AI-powered phishing campaign known as EvilTokens took the spotlight in the infosec world. While the term "AI-powered" is often used as a buzzword these days, it was certainly fitting for this campaign, as [an article by Huntress](https://www.huntress.com/blog/device-code-phishing-ai-mfa-bypass) outlined the use of AI in bypassing email filters, generating phishing lures, and even identifying potential targets for the campaign. Adding to the power of the EvilTokens campaign was the fact that it was sold as a Phishing-as-a-Service (PhaaS) platform for as little as a few hundred dollars USD, with full access to the platform costing a mere $1,500 — trivial for most cybercrime organizations.

## Identifying the campaign

The EvilTokens campaign can be identified by a number of indicators. First, despite AI generating a number of unique subject lines, the overall lure theme revolved around a small handful of topics, including bid proposals or RFPs, bogus DocuSigns, fake voicemails, and bogus HR documents. Next was the use of legitimate security vendor redirects — URLs related to Trend Micro, Mimecast, and Cisco — to give the impression of a legitimate link, which would then redirect to the actual phishing landing page. On top of these, the campaign leveraged high-reputation serverless platforms such as Vercel, Cloudflare Workers, and AWS Lambda to host the redirection, further obfuscating the phishing traffic, [as reported by Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/).

Ultimately, the phishing lure would land at a device code authorization flow page — a technique growing in popularity among threat actors that tricks the victim into copying an attacker-controlled device code into a legitimate Microsoft authorization prompt. That hands the attacker access to the victim's M365 account, enabling token theft and, ultimately, unauthorized access into the victim's M365 tenant.

## The detection

With the above in mind, detecting the campaign is actually quite simple. In one campaign observed by the author, phishing emails matching all of the above characteristics were hitting user inboxes spoofed as coming from the potential victim themselves. The spoofing should immediately throw red flags on SPF, DKIM, and DMARC — and indeed it did — though the email protections at the time did not stop these spoofed emails from hitting user inboxes rather than quarantine or junk. Thankfully, through a single KQL detection query paired with Microsoft Defender for Endpoint (MDE) automation rules, we can build a workflow that quickly deals with these emails.

Let's start with the query:

```kql
EmailEvents
| where tolower(RecipientEmailAddress) == tolower(SenderFromAddress)
| extend DKIMcheck = tostring(parse_json(AuthenticationDetails).DKIM)
| extend DMARCcheck = tostring(parse_json(AuthenticationDetails).DMARC)
| where DKIMcheck contains "none" and DMARCcheck !contains "pass"
| where DeliveryLocation contains "Inbox/folder"
| where not(EmailDirection contains "Intra-org")
| project TimeGenerated, DKIMcheck, DMARCcheck, DeliveryAction, DeliveryLocation,
          RecipientEmailAddress, SenderFromAddress, SenderIPv4, Subject,
          NetworkMessageId, EmailDirection
```

This query leverages the `EmailEvents` table available in Microsoft Sentinel and MDE, which logs email activity within the M365 tenant. We're looking specifically at emails where the sender and recipient are identical, indicating the spoofing described above. From there, we extract additional DKIM and DMARC details from the JSON-formatted `AuthenticationDetails` column and filter to find only emails that fail both. Last, we filter on `DeliveryLocation` to show only emails that land in user inboxes, and filter out intra-org communication to remove false positives. This query showed a 100% success rate at catching every single phishing email attributed to the EvilTokens campaign.

## Operationalizing with MDE automation

Once this query is operationalized in MDE, you have the option to set automated actions any time the query fires. An unfortunate intricacy of MDE is that while many tables allow for Near Real Time (NRT) querying and actions, some — including `EmailEvents` — do not, though the next best option is every 5 minutes.

For this query, we set the MDE automated action to run every 5 minutes and delete any emails the query detects. The end effect: while emails may technically still hit user inboxes, they are soft-deleted within 5 minutes — most often before the user has the opportunity to view the email, follow the link, and potentially be phished.

Within 48 hours of implementing this query and automation, over 1,200 malicious emails were prevented from being accessed by users, virtually nullifying the entire campaign's effect on the target organization.

## The takeaway

With powerful AI becoming commonplace in both the attacker and defender lifecycle, the barrier to entry for sophisticated phishing has never been lower, and defenders should expect campaigns like this to become the norm rather than the exception. But as flashy as the "AI-powered" label may be, this campaign also proves that the fundamentals still win. A single well-crafted KQL query paired with a 5-minute automation loop was enough to neutralize over 1,200 malicious emails in two days. No expensive tooling, no LLMs — just a sharp eye for the anomalies attackers can't avoid creating.

The takeaway for defenders is simple: when attackers innovate at the lure layer, look for the unchanging fundamentals underneath.

*Originally published on [Medium](https://medium.com/@mattcswann/how-a-single-kql-query-stopped-an-entire-eviltokens-phishing-campaign-9b9dd4e32920).*
