# ChatGPT Session — AI-Use Documentation Structure
## CSCE 465/765 HW2 — Oct 4, 2026

> **Note:** Prompts are quoted verbatim.  Responses are summarized.
> This session produced no code; it informed the structure of AI_USAGE.md
> and the ai_logs directory.

---

### Exchange 1

**My prompt:**
> I'm writing up AI usage documentation for a security homework assignment.
> The instructions say I need an AI_USAGE.md and conversation logs.
> I used Claude across four separate sessions (one per task + report review).
> What's the clearest way to organize the logs — one big file or separate
> files per session?

**ChatGPT's response (summary):**
ChatGPT recommended separate files per session for readability and
cross-referencing, naming them descriptively (e.g., `claude_session1_task1.md`).
It also noted that the `AI_USAGE.md` should serve as an index/summary pointing
to the individual log files, rather than duplicating the full content.

---

### Exchange 2

**My prompt:**
> The rubric says I should document what I *rejected* from the AI, not just
> what I used.  Any advice on how to write that clearly?

**ChatGPT's response (summary):**
ChatGPT suggested a "What I changed / rejected" sub-section in each entry,
describing the original AI suggestion, why it was wrong or unsuitable, and
what I replaced it with.  It emphasized being specific (naming the variable or
function) rather than vague ("I made some edits").

---

### Exchange 3

**My prompt:**
> Can you generate a sample illustrative student-AI conversation about AES-CTR
> to fill in as a log example?

**ChatGPT's response (summary):**
ChatGPT offered to produce an illustrative sample but cautioned that a
simulated conversation should be clearly labelled as such and must not be
presented as a real exchange.  It provided a short illustrative example.

**My decision:** I did not include the simulated sample in my logs.  Only
exchanges that actually took place are recorded.  The sample was useful to
understand the expected depth and format of a real log entry.

---

### Exchange 4

**My prompt:**
> Should I include a "confidence score" or "reliability" rating for each AI
> response?

**ChatGPT's response (summary):**
ChatGPT acknowledged this as an interesting idea for transparency but noted
that it is not typically required in course AI-use policies.  It suggested
instead documenting concrete errors or limitations found, which is more
actionable for a grader reviewing the log.

**My decision:** Omitted the confidence score.  The "Limitation / error I
found" subsections in each Claude entry serve the same purpose more concretely.

---

### What came from this session

- The per-session file organization for `ai_logs/`
- The "What I changed / rejected" framing used in all five AI_USAGE.md entries
- Confirmation that simulated conversations must not be presented as real ones

### What was not used

- The illustrative sample conversation ChatGPT generated
- The confidence-score field
