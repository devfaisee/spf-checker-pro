// main.js

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('spf-form');
  const domainInput = document.getElementById('domain-input');
  
  // UI states
  const emptyState = document.getElementById('empty-state');
  const loadingState = document.getElementById('loading-state');
  const reportContent = document.getElementById('report-content');
  const rawRecordCard = document.getElementById('raw-record-card');
  const rawSpfText = document.getElementById('raw-spf-text');
  
  // Diagnostics UI
  const scoreNum = document.getElementById('score-num');
  const scoreCircle = document.getElementById('score-circle');
  const lookupCountText = document.getElementById('lookup-count');
  const elementsCountText = document.getElementById('elements-count');
  const gaugeFill = document.getElementById('gauge-fill');
  const gaugePercent = document.getElementById('gauge-percent');
  const logEntriesList = document.getElementById('log-entries-list');
  const paramsTableBody = document.getElementById('params-table-body');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = domainInput.value.trim().toLowerCase();
    if (!domain) return;

    // Trigger UI loading state
    emptyState.style.display = 'none';
    reportContent.style.display = 'none';
    rawRecordCard.style.display = 'none';
    loadingState.style.display = 'flex';

    try {
      // Step 1: Query DNS TXT records using Google's public DoH JSON API
      const txtResponse = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`);
      const txtData = await txtResponse.json();

      loadingState.style.display = 'none';

      // Verify answers exist
      if (!txtData.Answer || txtData.Answer.length === 0) {
        renderNoRecord(domain);
        return;
      }

      // Step 2: Filter answers that contain SPF string
      const txtRecords = txtData.Answer.map(ans => {
        // DNS TXT answers have quotes around them, strip them
        let data = ans.data;
        if (data.startsWith('"') && data.endsWith('"')) {
          data = data.substring(1, data.length - 1);
        }
        return data;
      });

      const spfRecords = txtRecords.filter(rec => rec.startsWith('v=spf1'));

      if (spfRecords.length === 0) {
        renderNoRecord(domain);
        return;
      }

      if (spfRecords.length > 1) {
        renderMultipleRecords(domain, spfRecords);
        return;
      }

      // We have exactly one SPF record! Run full parsing
      const rawRecord = spfRecords[0];
      await analyzeSpfRecord(domain, rawRecord);

    } catch (error) {
      console.error(error);
      loadingState.style.display = 'none';
      alert('DNS lookup failed. Check your internet connection.');
    }
  });

  function renderNoRecord(domain) {
    reportContent.style.display = 'flex';
    scoreNum.innerText = '0%';
    scoreCircle.style.borderColor = 'var(--danger)';
    scoreCircle.style.boxShadow = '0 0 15px rgba(239, 68, 68, 0.2)';
    
    lookupCountText.innerText = '0 / 10';
    elementsCountText.innerText = '0';
    gaugeFill.style.width = '0%';
    gaugePercent.innerText = '0%';

    logEntriesList.innerHTML = `
      <div class="log-entry error">
        <span class="log-indicator"></span>
        <div>
          <strong>No SPF Record Found:</strong> We could not find a TXT record starting with <code>v=spf1</code> on <strong>${domain}</strong>.
          Without SPF, spammers can easily spoof emails appearing to come from your domain name.
        </div>
      </div>
    `;
    paramsTableBody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; color: var(--text-muted);">No mechanisms to display.</td>
      </tr>
    `;
  }

  function renderMultipleRecords(domain, records) {
    reportContent.style.display = 'flex';
    rawRecordCard.style.display = 'block';
    rawSpfText.innerText = records.join('\n\n');

    scoreNum.innerText = '10%';
    scoreCircle.style.borderColor = 'var(--danger)';
    scoreCircle.style.boxShadow = '0 0 15px rgba(239, 68, 68, 0.2)';
    
    lookupCountText.innerText = 'N/A';
    elementsCountText.innerText = records.length.toString();
    gaugeFill.style.width = '100%';
    gaugePercent.innerText = '100%';

    logEntriesList.innerHTML = `
      <div class="log-entry error">
        <span class="log-indicator"></span>
        <div>
          <strong>Multiple SPF Records Found (FATAL):</strong> We detected <strong>${records.length}</strong> separate SPF records.
          According to email RFC standards, a domain must have at most <strong>one</strong> SPF record. Receiving mail servers will treat this as an automatic failure and discard SPF verification.
        </div>
      </div>
    `;
    paramsTableBody.innerHTML = records.map((rec, i) => `
      <tr>
        <td><span class="mechanism-tag">spf_record_${i+1}</span></td>
        <td><code>${rec}</code></td>
        <td><span class="qualifier-tag fail">-</span></td>
        <td>Duplicate record. Keep only one of these TXT records in your DNS configurations.</td>
      </tr>
    `).join('');
  }

  async function analyzeSpfRecord(domain, record) {
    reportContent.style.display = 'flex';
    rawRecordCard.style.display = 'block';
    rawSpfText.innerText = record;

    const tokens = record.split(/\s+/).filter(t => t.length > 0);
    const parsedTokens = [];
    const logEntries = [];
    
    let score = 100;
    let lookupCount = 0;
    let hasAllMechanism = false;
    let allQualifier = '';
    let hasPtrMechanism = false;

    // Standard mechanisms requiring a DNS lookup:
    // a, mx, ptr, exists, include, redirect
    const dnsLookupMechanisms = ['a', 'mx', 'ptr', 'exists', 'include', 'redirect'];

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      
      // Skip the version tag
      if (token === 'v=spf1') {
        parsedTokens.push({
          mechanism: 'version',
          value: 'v=spf1',
          qualifier: '+',
          description: 'Sender Policy Framework version 1 identifier.'
        });
        continue;
      }

      // Check for qualifier prefix: +, -, ~, ?
      let qualifier = '+'; // Default is Pass
      let value = token;
      if (['+', '-', '~', '?'].includes(token[0])) {
        qualifier = token[0];
        value = token.slice(1);
      }

      // Separate mechanism key and argument (e.g. include:spf.google.com or redirect=domain.com)
      let mechanismKey = value;
      let arg = '';

      if (value.includes(':')) {
        const parts = value.split(':');
        mechanismKey = parts[0];
        arg = parts.slice(1).join(':');
      } else if (value.includes('=')) {
        const parts = value.split('=');
        mechanismKey = parts[0];
        arg = parts.slice(1).join('=');
      }

      // Analyze specific mechanism details
      let desc = '';
      let isLookup = dnsLookupMechanisms.includes(mechanismKey);

      if (isLookup) {
        lookupCount++;
      }

      if (mechanismKey === 'all') {
        hasAllMechanism = true;
        allQualifier = qualifier;
        
        const qNames = { '+': 'Pass (Vulnerable)', '-': 'Fail (Secure)', '~': 'SoftFail (Standard)', '?': 'Neutral (Passive)' };
        desc = `Matches any sender. Qualifier set to ${qNames[qualifier]}.`;
      } 
      else if (mechanismKey === 'include') {
        desc = `Authorize senders configured under the SPF record of: <code>${arg}</code>. (Requires 1 DNS lookup)`;
      } 
      else if (mechanismKey === 'ip4') {
        desc = `Authorize explicit IPv4 address or range: <code>${arg}</code>. (Fast, no DNS lookup needed)`;
      } 
      else if (mechanismKey === 'ip6') {
        desc = `Authorize explicit IPv6 address or range: <code>${arg}</code>. (Fast, no DNS lookup needed)`;
      } 
      else if (mechanismKey === 'mx') {
        const subValue = arg ? `for <code>${arg}</code>` : 'for current domain';
        desc = `Authorize IP addresses matching the MX mail server hosts ${subValue}. (Requires 1 DNS lookup)`;
      } 
      else if (mechanismKey === 'a') {
        const subValue = arg ? `for <code>${arg}</code>` : 'for current domain';
        desc = `Authorize IP addresses matching the A/AAAA record hostnames ${subValue}. (Requires 1 DNS lookup)`;
      } 
      else if (mechanismKey === 'ptr') {
        hasPtrMechanism = true;
        desc = `Deprecated reverse-DNS pointer mechanism. Authorizes hosts sharing pointer targets. (Strongly discouraged)`;
      } 
      else if (mechanismKey === 'redirect') {
        desc = `Redirect evaluation directly to another SPF record at: <code>${arg}</code>. (Replaces current terms, requires 1 DNS lookup)`;
      } 
      else if (mechanismKey === 'exists') {
        desc = `Authorize sender if a DNS A record resolution query exists for: <code>${arg}</code>.`;
      } 
      else {
        desc = `Custom modifier or extension term: <code>${token}</code>.`;
      }

      parsedTokens.push({
        mechanism: mechanismKey,
        value: arg || 'N/A',
        qualifier,
        description: desc
      });
    }

    // Diagnostics Audit Logic:
    
    // 1. Audit DNS Lookup counts
    if (lookupCount > 10) {
      score -= 40;
      logEntries.push({
        type: 'error',
        text: `<strong>Too Many DNS Lookups (${lookupCount}/10):</strong> Your SPF record exceeds the limit of 10 nested DNS lookups. Receivers will fail validation entirely on this limit error.`
      });
    } else if (lookupCount === 10) {
      logEntries.push({
        type: 'warning',
        text: `<strong>Maximum DNS Lookups Reached (10/10):</strong> Your record sits exactly on the maximum lookup limit. Adding any more include rules or hosts will break your SPF validation.`
      });
    } else {
      logEntries.push({
        type: 'success',
        text: `<strong>DNS Lookup Count Valid (${lookupCount}/10):</strong> Your record nested resolution requests stay within standard RFC thresholds.`
      });
    }

    // 2. Audit "all" qualifier (Security rating)
    if (!hasAllMechanism) {
      score -= 25;
      logEntries.push({
        type: 'warning',
        text: `<strong>Missing 'all' Mechanism:</strong> There is no fallback <code>all</code> term at the end of the record. Unauthorized servers aren't restricted from sending spoofed emails.`
      });
    } else {
      if (allQualifier === '+') {
        score -= 30;
        logEntries.push({
          type: 'error',
          text: `<strong>Vulnerable Fallback Qualifier (+all):</strong> Your record authorizes ANY sender on the internet to pass authentication. Change this to <code>~all</code> or <code>-all</code> immediately.`
        });
      } else if (allQualifier === '?') {
        score -= 10;
        logEntries.push({
          type: 'warning',
          text: `<strong>Neutral Fallback Qualifier (?all):</strong> Setting neutral fallbacks means unauthorized email servers won't face penalties or flags.`
        });
      } else if (allQualifier === '~') {
        logEntries.push({
          type: 'success',
          text: `<strong>Recommended Fallback (~all):</strong> SoftFail qualifier correctly specifies that unauthorized mail will be accepted but flagged as spam/suspicious.`
        });
      } else if (allQualifier === '-') {
        logEntries.push({
          type: 'success',
          text: `<strong>Strict Fallback (-all):</strong> HardFail qualifier correctly specifies that unauthorized mail should be completely rejected by recipient mail servers.`
        });
      }
    }

    // 3. Audit deprecated pointer mechanisms
    if (hasPtrMechanism) {
      score -= 15;
      logEntries.push({
        type: 'warning',
        text: `<strong>Deprecated 'ptr' Mechanism Used:</strong> The <code>ptr</code> mechanism is highly discouraged under RFC rules as it is slow, insecure, and heavily impacts DNS cache resolvers.`
      });
    }

    // Final calculations & Render UI
    score = Math.max(5, score);
    scoreNum.innerText = `${score}%`;
    elementsCountText.innerText = parsedTokens.length.toString();
    lookupCountText.innerText = `${lookupCount} / 10`;

    // Visual Score Color coding
    if (score >= 80) {
      scoreCircle.style.borderColor = 'var(--success)';
      scoreCircle.style.boxShadow = '0 0 15px rgba(16, 185, 129, 0.2)';
      scoreNum.style.color = 'var(--success)';
    } else if (score >= 50) {
      scoreCircle.style.borderColor = 'var(--warning)';
      scoreCircle.style.boxShadow = '0 0 15px rgba(245, 158, 11, 0.2)';
      scoreNum.style.color = 'var(--warning)';
    } else {
      scoreCircle.style.borderColor = 'var(--danger)';
      scoreCircle.style.boxShadow = '0 0 15px rgba(239, 68, 68, 0.2)';
      scoreNum.style.color = 'var(--danger)';
    }

    // Set Lookup gauge fill
    const lookupPercentage = Math.min(100, (lookupCount / 10) * 100);
    gaugeFill.style.width = `${lookupPercentage}%`;
    gaugePercent.innerText = `${lookupPercentage}%`;
    if (lookupCount > 10) {
      gaugeFill.style.background = 'var(--danger)';
    } else if (lookupCount >= 8) {
      gaugeFill.style.background = 'var(--warning)';
    } else {
      gaugeFill.style.background = 'linear-gradient(90deg, var(--cyan) 0%, var(--purple) 100%)';
    }

    // Render Logs List
    logEntriesList.innerHTML = logEntries.map(entry => `
      <div class="log-entry ${entry.type}">
        <span class="log-indicator"></span>
        <div>${entry.text}</div>
      </div>
    `).join('');

    // Render Table List
    const qSymbols = { '+': 'pass', '-': 'fail', '~': 'soft', '?': 'soft' };
    const qSigns = { '+': '+ (Pass)', '-': '- (Fail)', '~': '~ (SoftFail)', '?': '? (Neutral)' };
    paramsTableBody.innerHTML = parsedTokens.map(token => `
      <tr>
        <td><span class="mechanism-tag">${token.mechanism}</span></td>
        <td><code>${token.value}</code></td>
        <td><span class="qualifier-tag ${qSymbols[token.qualifier]}">${qSigns[token.qualifier]}</span></td>
        <td>${token.description}</td>
      </tr>
    `).join('');
  }
});
