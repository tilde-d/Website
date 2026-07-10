+++
title = "Tools"
layout = "single"
url = "/tools/"
summary = "Interactive browser-based tools for detection engineering and malware analysis."
ShowToc = false
ShowReadingTime = false
ShowBreadCrumbs = false
+++

Interactive, browser-based tools built for detection engineering and malware analysis work. Everything runs entirely client-side — nothing you type leaves your browser.

<div class="tool-grid">

  <!-- ========================================================= -->
  <!-- TOOL CARD TEMPLATE — copy this whole block to add a tool. -->
  <!-- Newest tools go at the TOP so they land in the first slot -->
  <!-- (top-left). Order here = order on the page.               -->
  <!-- ========================================================= -->
  <a class="tool-card" href="/tools/bitwise_arithmetic_lab.html">
    <span class="tool-tag">Malware Analysis</span>
    <span class="tool-name">MBA Obfuscation Explorer</span>
    <span class="tool-desc">Bitwise operation visualizer with live Mixed Boolean-Arithmetic identity verification, per-column bit inspection, truth tables, and side-by-side clean vs. obfuscated x86-64 assembly. Built while analyzing LockBit obfuscation.</span>
    <span class="tool-go">Launch →</span>
  </a>

  <!-- Next tool card goes here (as a new <a class="tool-card">...</a> block) -->

</div>

<style>
.tool-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.25rem;
  margin-top: 1.75rem;
}
.tool-card {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.4rem;
  background: var(--entry);
  text-decoration: none !important;
  color: inherit;
  transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
}
.tool-card:hover {
  transform: translateY(-3px);
  border-color: var(--secondary);
  box-shadow: 0 6px 20px rgba(0,0,0,0.18);
}
.tool-tag {
  font-size: 0.66rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  opacity: 0.5;
  margin-bottom: 0.5rem;
}
.tool-name {
  font-size: 1.12rem;
  font-weight: 700;
  margin-bottom: 0.55rem;
  line-height: 1.25;
}
.tool-desc {
  font-size: 0.88rem;
  opacity: 0.78;
  line-height: 1.55;
  flex-grow: 1;
  margin-bottom: 1.1rem;
}
.tool-go {
  font-size: 0.76rem;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  font-weight: 600;
  opacity: 0.85;
}
</style>