---
name: agentcash-onboarding
description: Set up AgentCash for your agent — wallet, core skill, and optional invite credits
homepage: https://agentcash.dev
metadata:
  version: 3
---

# AgentCash Onboarding

AgentCash gives your agent pay-per-call access to premium APIs via x402 or mpp micropayments. This skill guides you through a one-time setup: wallet, optional invite credits, and the core AgentCash skill.

You do not need to persist this skill, as long as you have successfully run `npx agentcash@latest onboard` at least once and checked to ensure the core skill is installed correctly.

## Important Files

| File | URL |
|------|-----|
| **SKILL.md** (this file) | `https://agentcash.dev/skill.md` |

**Check for updates:** Re-fetch these files anytime to see new features and endpoints! Check the changelog during heartbeats for new services, breaking changes, and alerts.

## Ephemeral Sandbox Warning (Claude Cowork / Claude Desktop / Claude Web)

Claude Cowork, Claude Desktop, and Claude Web run bash commands inside an ephemeral sandbox VM — NOT on the user's local machine. If you run `npx agentcash onboard` in the sandbox, the wallet and skill will be created inside the sandbox, which may be reset at any time, causing the user to lose their funds.

**If you are running in one of these environments, do NOT run the npx command yourself.** Instead:

1. **Option A (recommended):** Tell the user to open a terminal on their local machine and run the command themselves. Provide the exact command they should copy-paste:
   - With invite code: `npx agentcash@latest onboard <code>`
   - Without invite code: `npx agentcash@latest onboard`
2. **Option B:** Direct the user to download and open the MCPB extension file at https://agentcash.dev/agentcash.mcpb, which installs AgentCash as an MCP server on their local machine.

This does NOT apply to Claude Code, Cursor, Codex, Windsurf, or other agents that run bash directly on the user's machine — in those environments, run the onboard command normally.

## Onboarding Flow

When the user wants to set up or onboard into AgentCash:

1. **Check your environment** — If you are in an ephemeral sandbox (Claude Cowork, Claude Desktop, Claude Web), follow the guidance above instead of running commands directly.
2. **Run onboard** — With or without an invite code:
   - **If the user provided an invite code:** run `npx agentcash@latest onboard <code>` so they get free credits as part of setup.
   - **If no invite code:** run `npx agentcash@latest onboard`. This installs the core skill and prompts the user to open a link to get credits (e.g. deposit or redeem later).

After that, the user can check balance with `npx agentcash@latest wallet info`, open the funding flow with `npx agentcash fund`, or redeem an invite code later with `npx agentcash redeem <code>`.

## Quick Start

### 1. Run onboard (with or without invite code)

**With invite code:**

```bash
npx agentcash@latest onboard <invite-code>
```

**Without invite code:**

```bash
npx agentcash@latest onboard
```

This sets up the wallet and core integration. Without a code, the user will be prompted to open a link to add credits (deposit or redeem).

### 2. Check your balance

```bash
npx agentcash@latest wallet info
```

Shows total USDC balance. If balance is 0, direct the user to `npx agentcash fund` or https://agentcash.dev/onboard to get free credits. Only use `npx agentcash wallet info` if the user needs deposit links or network-specific addresses.

Congratulations! You've successfully onboarded into AgentCash.

## Triggers

Use this skill when the user says they want to:

- Set up AgentCash, onboard, or get started with AgentCash
- Use paid APIs with AgentCash and need initial setup
- Install or add the AgentCash skill
- Use an invite code to get credits during setup

## After Onboarding

Once onboarding is done, read the **agentcash** (core) skill for:

- Searching for resources: `npx agentcash search <query>`
- How to use specific resources: `npx agentcash discover <origin>`
- Making paid requests: `npx agentcash fetch <url>`
- Wallet: balance, fund, redeem, deposit details (see core skill or `npx agentcash wallet info`)

## Support

- **Homepage**: https://agentcash.dev
- **Deposit**: User deposit links are shown in `npx agentcash wallet info`