---
tags:
  - OSCP
  - Exam
  - Workflow
  - Foundational
---

## OSCP Exam Strategy
resources: [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide), [TJNull's List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159)

> Proven strategies for time management and point accumulation during the OSCP exam.

## Time Management

> [!important] Focus on one machine at a time - don't switch between machines every 30 minutes.

### First Attempt Mistake
**Problem:** Switching between machines while waiting for tasks
- Working on machine X while hash cracking on machine Y
- Constantly context switching
- Lost focus and momentum
- **Result:** Failed exam after 24 hours

### Second Attempt Success
**Strategy:** Fully compromise each machine sequentially
- Started at 7 AM
- Rooted three individual machines by 1 PM (6 hours)
- Accumulated 60 points + 10 bonus = 70 points (PASS)
- Didn't need to compromise AD set

> [!tip] Complete each machine 100% before moving to the next one.

## Point Accumulation Strategy

### Minimum to Pass: 70 Points

**Option 1: Three Standalone Machines + Bonus**
- Machine 1 (user + root): 20 points
- Machine 2 (user + root): 20 points
- Machine 3 (user + root): 20 points
- Bonus points (lab report): 10 points
- **Total: 70 points (PASS)**

**Option 2: Two Standalone + AD Set + Bonus**
- Machine 1 (user + root): 20 points
- Machine 2 (user + root): 20 points
- AD set (full compromise): 40 points
- Bonus points: 10 points
- **Total: 90 points**

**Option 3: AD Set + One Standalone + Bonus**
- AD set (full compromise): 40 points
- Machine 1 (user + root): 20 points
- Bonus points: 10 points
- **Total: 70 points (PASS)**

> [!tip] Bonus points can be the difference between pass and fail.

## Bonus Points Strategy

### How to Earn 10 Bonus Points

**Requirements:**
1. Complete all PWK course exercises
2. Document 10 Proving Grounds machines
3. Submit comprehensive lab report

**Why bonus points matter:**
- Provides 10-point buffer
- Can pass without compromising AD set
- Reduces exam pressure
- Allows for partial credit scenarios

> [!important] Start working on bonus points early - don't wait until exam week.

## Machine Compromise Order

### Recommended Approach

**Step 1: Enumerate All Machines (30 minutes)**
```bash
# Quick nmap scan of all targets
nmap -p- -T4 192.168.1.10 -oA nmap/machine1 &
nmap -p- -T4 192.168.1.11 -oA nmap/machine2 &
nmap -p- -T4 192.168.1.12 -oA nmap/machine3 &
```

**Step 2: Identify Easiest Target (15 minutes)**
- Review nmap results
- Look for obvious vulnerabilities
- Check for known exploits
- Identify low-hanging fruit

**Step 3: Fully Compromise First Machine (2-4 hours)**
- Get initial foothold
- Escalate to user
- Escalate to root/SYSTEM
- Capture proof.txt and local.txt
- Document everything

**Step 4: Repeat for Remaining Machines**
- Move to next easiest target
- Complete 100% before switching
- Document as you go

**Step 5: AD Set (If Needed)**
- Only attempt if you need more points
- Can skip if you have 70+ points already

> [!warning] Don't start AD set until you've rooted at least 2 standalone machines.

## Time Allocation

### 24-Hour Exam Timeline

**Hours 1-2: Initial Enumeration**
- Scan all machines
- Identify attack vectors
- Prioritize targets

**Hours 3-8: First Machine**
- Initial access
- User privilege
- Root privilege
- Documentation

**Hours 9-14: Second Machine**
- Repeat process
- Full compromise
- Documentation

**Hours 15-20: Third Machine**
- Final standalone machine
- Full compromise
- Documentation

**Hours 21-24: AD Set or Buffer**
- Attempt AD if needed
- Review documentation
- Verify all screenshots
- Rest if you have enough points

> [!tip] If you have 70+ points by hour 15, take a break and review your documentation.

## Common Time Wasters

### Avoid These Mistakes

1. **Rabbit Holes**
   - Set 30-minute limit on any single approach
   - If stuck, enumerate more or try different vector
   
2. **Brute Forcing**
   - Maximum 10 minutes per username
   - If rockyou.txt doesn't work, move on
   
3. **Overthinking**
   - OSCP is about fundamentals, not advanced exploits
   - Try simple things first (default creds, misconfigurations)
   
4. **Poor Documentation**
   - Document as you go, not at the end
   - Screenshots with timestamps
   - Command history saved

5. **Switching Machines Too Often**
   - Finish one machine completely
   - Don't multitask between targets

## Break Strategy

### When to Take Breaks

**Mandatory Breaks:**
- After rooting each machine (15 minutes)
- Every 4 hours (10 minutes)
- If stuck for 1 hour (30-minute break)

**What to Do During Breaks:**
- Step away from computer
- Eat/drink
- Clear your mind
- Review notes with fresh eyes

> [!warning] Don't skip breaks - they improve performance and prevent burnout.

## Documentation During Exam

### Real-Time Documentation

**What to Document:**
- Every command executed
- Every exploit attempted (even failures)
- Screenshots of proof.txt and local.txt
- Full attack path from initial access to root
- Timestamps for everything

**Tools:**
- CherryTree (recommended)
- Obsidian
- Markdown notes
- Screenshot tool (Flameshot, Greenshot)

**Screenshot Requirements:**
- proof.txt with `ipconfig`/`ifconfig`
- local.txt with `ipconfig`/`ifconfig`
- Timestamp visible in terminal

> [!important] Take screenshots immediately after getting flags - don't wait.

## Post-Exam Report

### 24-Hour Report Window

**After Exam Ends:**
- You have 24 hours to submit report
- Report must be professional and detailed
- Include all screenshots and commands
- Follow OffSec report template

**Report Structure:**
1. Executive Summary
2. High-Level Summary (point breakdown)
3. Methodology
4. Machine 1 Walkthrough
5. Machine 2 Walkthrough
6. Machine 3 Walkthrough
7. AD Set Walkthrough (if applicable)
8. Appendix (proof screenshots)

> [!tip] Use the official OffSec report template - don't create your own format.

## Mental Preparation

### Exam Day Mindset

**Before Exam:**
- Get good sleep (8 hours)
- Eat healthy breakfast
- Set up workspace
- Test VPN connection
- Have snacks and water ready

**During Exam:**
- Stay calm and methodical
- Trust your methodology
- Don't panic if stuck
- Remember: you've done this in labs

**If Failing:**
- You can retake the exam
- Learn from mistakes
- Review weak areas
- Practice more on Proving Grounds

> [!important] OSCP is about methodology, not memorization. Follow your process.

## Final Checklist

### Pre-Exam Preparation

- [ ] Earned 10 bonus points (lab report + exercises)
- [ ] Practiced on TJNull's list machines
- [ ] Comfortable with manual exploitation
- [ ] Can stabilize shells without Metasploit
- [ ] Know BloodHound enumeration
- [ ] Understand pivoting (Chisel/Ligolo-NG)
- [ ] Have documentation template ready
- [ ] Know common privilege escalation vectors
- [ ] Practiced time management
- [ ] Tested all tools in lab environment
- [ ] VPN connection tested
- [ ] Workspace organized
- [ ] Snacks and water prepared
- [ ] Sleep schedule adjusted

### Exam Day Checklist

- [ ] Connect to VPN
- [ ] Verify all machines are reachable
- [ ] Start documentation template
- [ ] Begin initial enumeration
- [ ] Focus on one machine at a time
- [ ] Take breaks every 4 hours
- [ ] Document everything in real-time
- [ ] Capture all required screenshots
- [ ] Verify proof.txt and local.txt screenshots
- [ ] Review documentation before exam ends

## Success Metrics

### You're Ready If:

1. **You can root 3 TJNull machines in 8 hours**
2. **You can enumerate AD with BloodHound**
3. **You can pivot through dual-homed machines**
4. **You can stabilize shells manually**
5. **You understand common privilege escalation**
6. **You can document as you work**
7. **You don't rely on Metasploit**
8. **You've earned bonus points**

> [!tip] If you can consistently root TJNull machines, you're ready for the exam.

## Remember

**OSCP is a marathon, not a sprint:**
- Pace yourself
- Stay methodical
- Trust your training
- Don't give up

**You only need 70 points to pass:**
- 3 machines + bonus = 70 points
- You don't need to root everything
- Partial credit is possible

**The exam tests methodology:**
- Enumeration
- Exploitation
- Privilege escalation
- Documentation

> [!important] Try Harder, but also Try Smarter. Good luck!
