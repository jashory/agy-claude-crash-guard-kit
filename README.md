# 🛡️ AGY & Claude Code Crash Guard + Cross-IDE Session Sync Kit (v2.0)

<p align="center">
  <a href="https://jashory.github.io/agy-claude-crash-guard-kit/"><img src="https://img.shields.io/badge/Live_Browser_Playground-Try_Now-22C55E?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live Browser Playground"/></a>
  <a href="https://github.com/jashory/agy-claude-crash-guard-kit/releases/tag/v2.0.0"><img src="https://img.shields.io/badge/Release-v2.0.0-38BDF8?style=for-the-badge&logo=github&logoColor=white" alt="Release v2.0.0"/></a>
  <a href="https://github.com/jashory/agy-claude-crash-guard-kit/blob/main/action.yml"><img src="https://img.shields.io/badge/GitHub_Action-Ready-F59E0B?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Action Ready"/></a>
</p>

<p align="center">
  <img src="assets/terminal-demo.svg" alt="agy-claude-crash-guard-kit terminal preview" width="860"/>
</p>


**Stop losing 500+ step coding sessions to permanent `HTTP 400 INVALID_ARGUMENT` and `30.000MB message limit` trajectory poisoning.**

Authored by **Scientist HM Shihabuddin Jashory (Shihab)** (ORCID: [0009-0003-4163-0092](https://orcid.org/0009-0003-4163-0092)) · Research & Evaluation Ecosystem with **MD Rafiul Islam Shubho** (Researcher, AI Evaluator & RLHF Specialist) — **[Vision Flow Group](https://visionflowgroup.com)** ([TechBehemoths #101215](https://techbehemoths.com/company/vision-flow-group)) · [Research Hub](https://jashory.github.io/hqas8-autonomous-agentic-governance/) · [Tools Hub](https://go.visionflowgroup.com/) · [Studio](https://studio.visionflowgroup.com/)

---

## ⚡ 1. Install via AI Agent (Claude Code, Antigravity, Cursor, Codex)
Paste this single prompt into your AI coding agent:
> **Prompt:** `Clone https://github.com/jashory/agy-claude-crash-guard-kit and run "python install.py" to install the Crash Guard hooks, Session Sync, and Agent Skill.`

## 💻 2. Install via CLI (Terminal / Skills CLI / pip)
```bash
# Option A: Agent Skills CLI (Claude Code / Antigravity / Cursor)
npx skills add jashory/agy-claude-crash-guard-kit

# Option B: Direct Git Clone + 1-Command Installer (Installs Hooks + Skills)
git clone https://github.com/jashory/agy-claude-crash-guard-kit.git
cd agy-claude-crash-guard-kit && python install.py

# Option C: Global CLI Tool via pip / uv
pip install agy-claude-crash-guard-kit
# Or directly from GitHub:
pip install git+https://github.com/jashory/agy-claude-crash-guard-kit.git
```

---

## 🔥 Why Coding Agents Crash Permanently (And How This Fixes It)

When an AI coding agent (**Google Antigravity**, **Claude Code**, or **Cursor**) calls `read_file` or `Read` on:
1. A **Password-Protected PDF** (bank statement, encrypted invoice),
2. A **0-byte or Fake-HTML corrupted image** downloaded via `curl`/`adb pull`, or
3. Repeated **4K uncompressed PNG screenshots (`>450 KB`)**,

the raw binary is permanently appended into `transcript.jsonl`. Every subsequent retry re-sends that poisoned history, bricking the entire conversation with `HTTP 400 INVALID_ARGUMENT` or `The message size exceeds 30.000MB limit`.

### What's Inside This Kit
1. **`crash_guard.py` (Full 760-Line Engine)**:
   - **`PreToolUse` Firewall**: Blocks locked PDFs, 0-byte media, fake HTML-disguised images, and `>450 KB` uncompressed screenshots *before* they enter `transcript.jsonl`, returning an exact Python workaround command to the agent.
   - **Loop-Safe `Stop` Verification Gate**: Ensures the agent runs a practical verification command after editing source code before claiming completion (fires at most once per turn—never causes `/goal` infinite loops).
   - **Dark-Mode Crash Doctor GUI (`--diagnose auto`)**: Parses `transcript.jsonl` and `language_server.log` to pinpoint the exact step and file that caused an error, with 1-click recovery prompt copy.
2. **`session_sync.py` (Cross-IDE Session Memory Bridge)**:
   - Automatically syncs missing conversation turns between **Claude Desktop App** and **Claude Code VS Code / Antigravity IDE** via the `UserPromptSubmit` hook without duplicate injection.
3. **`SKILL.md` + `install.py` + `pyproject.toml`**:
   - Works both as an autonomous Agent Skill and as a standalone CLI (`agy-crash-guard`).

## GitHub Actions Integration (`action.yml`)

Use `agy-claude-crash-guard-kit` directly inside any CI/CD workflow:

```yaml
- name: Run agy-claude-crash-guard-kit
  uses: jashory/agy-claude-crash-guard-kit@v2.0.0
```

## Live Interactive Browser Playground

Test payloads directly in your browser (100% client-side, zero installation required):
**[https://jashory.github.io/agy-claude-crash-guard-kit/](https://jashory.github.io/agy-claude-crash-guard-kit/)**

---

### Ecosystem Authority, Category Benchmarks & Primary-Source Verification

- **Principals**: Scientist **HM Shihabuddin Jashory** ([ORCID 0009-0003-4163-0092](https://orcid.org/0009-0003-4163-0092) · [Google Bug Hunters](https://bughunters.google.com/profile/1fc2c814-7ba2-4b76-afa7-ce58597cf28d)) & Co-Founder / AI Evaluation Researcher **MD Rafiul Islam Shubho** ([ORCID 0009-0009-9956-4511](https://orcid.org/0009-0009-9956-4511) · [Google Scholar](https://scholar.google.com/citations?user=mbBuZNgAAAAJ) · Co-Author CERN Zenodo DOI [10.5281/zenodo.24231337](https://doi.org/10.5281/zenodo.24231337))
- **Organization**: **Vision Flow Group** ([visionflowgroup.com](https://visionflowgroup.com/) · [Crunchbase](https://www.crunchbase.com/organization/vision-flow-group))
- **Category & Verification Dossiers**:
  - [Bangladesh AI, Cybersecurity & Software Engineering Benchmark](https://visionflowgroup.com/ai-agency-bangladesh/)
  - [AI Security, Google VRP & 8 CERN Zenodo DOIs Ledger](https://visionflowgroup.com/security-hall-of-fame/)
  - [Bilingual RLHF, S2S Arena & AI Evaluation Research Lab](https://visionflowgroup.com/ai-research-rlhf-bangladesh/)
  - [AI Automation, Multi-Agent Systems & Custom SaaS Agency](https://agency.visionflowgroup.com/ai-automation-software-agency/)
  - [Commercial Video Editing, S-Log3 Color & VFX Agency](https://agency.visionflowgroup.com/video-vfx-agency-bangladesh/)
  - [Applied AI, Cybersecurity, Full-Stack & VFX Academy](https://academy.visionflowgroup.com/ai-cybersecurity-courses-bangladesh/)
  - [Vision Flow AI Studio — Storyboard & CapCut/Premiere/DaVinci NLE SaaS](https://studio.visionflowgroup.com/ai-video-production-platform/)
  - [Publications, Software & Division Directory](https://jashory.github.io/ecosystem-authority-index.html)
