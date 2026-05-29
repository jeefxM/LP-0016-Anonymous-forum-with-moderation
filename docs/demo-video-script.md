# Demo video runbook (LP-0016)

A recording guide, not a deliverable. Narrate in your own words; the bullets
are talking points, the code blocks are exactly what to put on screen. Target
length 8 to 12 minutes. The bounty needs narration (not a silent screencast),
an architecture + decisions walkthrough, the full lifecycle, and terminal
output that confirms `RISC0_DEV_MODE=0` and shows proof generation.

## Where everything runs

Segments 1, 2, 6 are you talking to camera (no screen needed). Segments 3, 4,
and 5 all run **on the Hetzner server**, not the Mac. That's where the RISC0
toolchain, the live daemon + nwaku + sequencer, and the testnet wallet live.

Simplest setup: open one terminal on the Mac, SSH into Hetzner, and
screen-record that terminal. Everything in 3 to 5 happens inside that one SSH
session. No tunnels, no switching machines.

Prep the session once (paste these after you SSH in, before recording):

```sh
ssh hetzner
export PATH=$HOME/.cargo/bin:$PATH
export NSSA_WALLET_HOME_DIR=~/wallet-testnet
cd ~/forum-protocol
```

## Before you hit record

Confirm the stack is up (on Hetzner):

```sh
tmux ls                       # expect: bedrock, seq, daemon
ps aux | grep sequencer_service | grep -o 'RISC0_DEV_MODE=[01]'   # expect 0
curl -s http://127.0.0.1:8787/v1/health                            # {"status":"ok",...}
```

Note: on Hetzner run the demo with `node scripts/demo.mjs` (not `just`); the
test command, the bench, and the wallet reads all run on Hetzner too.

Local checklist:
- Big terminal font, dark theme, wide window. Two panes help (commands left,
  a `tail -f ~/seq.log` right).
- Have these tabs ready: the repo in an editor (README, docs/protocol.md,
  docs/deployments.md), a terminal on the host, and the testnet wallet env
  (`NSSA_WALLET_HOME_DIR=~/wallet-testnet`).
- Decide on cuts: the chain steps in `just demo` take a couple of minutes. You
  can speed-ramp the waits in editing, but never cut the proof-generation shot
  or the `RISC0_DEV_MODE=0` reveal.

## Segment 1 — What and why (45s, talking head or a title slide)

**Say this (read aloud):**

> hey, so this is my submission for LP-0016, the anonymous forum with threshold
> moderation and membership revocation. real quick what it is. its a forum where
> you post completely anonymously, nobody can tell who you are and nobody can
> link your posts together. but it can still be moderated. if enough moderators
> agree you broke the rules, the system can actually unmask you, ban you, and
> take your deposit. and the whole point is the crypto enforces that, theres no
> admin who can just decide to unmask someone. i built two things here. a
> moderation library thats forum-agnostic, so any app can plug it in, and a
> reference app on top of it to show it working. and one thing i want to flag
> early, almost nothing touches the blockchain. posting and moderation all
> happen off-chain so theres no gas, the chain only gets hit when someone
> registers and when someone finally gets banned.

Stage directions / talking points:

- This is LP-0016: an anonymous forum with threshold moderation and membership
  revocation.
- Two deliverables: a forum-agnostic moderation SDK, and a reference Basecamp
  app built on it without modification.
- The property that matters: members post anonymously and their posts are
  unlinkable, yet an N-of-M moderator quorum can act on content, and a member
  who collects K strikes is revoked on-chain and retroactively deanonymized.
- Nothing touches the chain on the common path. Only registration and the final
  slash are on-chain; posting and moderation are off-chain over Waku.

## Segment 2 — Architecture and key decisions (2 to 3 min, screen-share)

**Say this (read aloud):**

> ok so let me walk through how this actually works. theres basically three
> layers, and the easiest way to picture it is like a private club. to join,
> you put down a deposit and you whisper a secret, and the system writes a
> scrambled version of your secret onto a big public list. your entry is on
> there, but nobody can tell which one is yours. thats the on-chain part, the
> membership registry, its a LEZ program and i built it with the SPEL framework
> so it ships an IDL like the bounty wants.
>
> then when you post, you attach a zero-knowledge proof that basically says
> "im one of the members on that list and im not banned," without pointing to
> which entry is you. thats the ZK layer, its a Groth16 circuit and it runs in
> under 10 seconds.
>
> the third layer is everything off-chain. the actual posts and the moderation
> certificates go over Waku, which is the logos messaging stack. so its free
> and anyone can audit it.
>
> now heres the clever part, the unmasking. every single post secretly carries
> one torn piece of your identity, using shamir secret sharing. one piece is
> useless, two pieces useless. moderation is N-of-M, so you need a quorum of
> moderators to agree before they can issue a strike, no single moderator can
> act alone. each strike grabs one of your pieces. once enough strikes pile up,
> thats the K threshold, the pieces tape back together and reconstruct your
> secret. then anyone can take that to the chain. it bans you, it keeps your
> stake, and now that your secret is out, all your past posts become linkable
> too. so the punishment basically is the unmasking, and it happens
> automatically from the math, not because some admin decided.
>
> all the reasoning behind these choices is written up in the ADRs and the
> protocol doc. the off-chain storage decision, the shamir threshold, the
> N-of-M signatures, the staking escrow, its all in there.

Stage directions / talking points:

Show the repo layout and `docs/protocol.md`. Walk the three layers:

1. On-chain membership registry, a LEZ program (RISC0 guest). Handles
   registration with stake, the revocation list, and slash verification. Built
   with the SPEL framework so it ships an IDL.
2. Off-chain over Waku: anonymous post envelopes and moderation certificates.
   Publicly auditable, no gas.
3. The ZK layer: a Groth16 membership proof (proves "I'm a registered,
   non-revoked member" without revealing which one) and a per-post nullifier.

Call out the decisions with their reasons (point at the ADRs):
- Waku-only off-chain storage so the common path is gasless (ADR-001).
- Semaphore-style commitment + nullifier for unlinkability (ADR-010); same
  epoch shares a nullifier, different epochs do not.
- Shamir secret sharing binds a share into every post; K moderation certs
  reconstruct the member's secret, which is what enables retroactive
  deanonymization on slash (ADR-008).
- N-of-M as a naive Ed25519 multi-signature certificate, threshold enforced
  client-side before anything goes on-chain (ADR-003).
- Staking via a registry-owned escrow PDA funded through authenticated_transfer
  (ADR-011).
- Ported the on-chain program to SPEL for the IDL and the testnet deploy
  (ADR-012).

Mention the anonymity set is the full set of non-revoked members, and point at
the threat model section in `docs/protocol.md`.

## Segment 3 — Tests and proof realness (1 to 2 min, terminal)

**Say this (read aloud):**

> first the tests. the bounty asks for a specific set of named tests and
> theyre all here, let me run them. *(run `cargo test`)* so you can see
> valid_registration, valid_post_proof, the two moderation cert ones,
> strike_accumulation, slash_submission, and post_rejection_after_revocation,
> all passing.
>
> now the proof part. the bounty wants real proofs with RISC0_DEV_MODE=0, not
> dev-mode fakes, so let me run the bench. *(run the bench)* you can see right
> at the top it prints RISC0_DEV_MODE equals 0, then it actually generates the
> proof and verifies it. quick honest note here, this specific guest is the
> original RISC0 post-proof. i later switched the live membership proof to
> Groth16 to hit that under-10-seconds target, so this shot is showing that
> real RISC0 proving works in the repo, and on the chain side RISC0_DEV_MODE=0
> is what governs the register and slash programs. and heres the sequencer
> itself, *(run the `ps` line)* you can see its also running with DEV_MODE=0,
> so theres no dev-mode shortcut anywhere.

Stage directions / talking points:

Show the seven bounty-named tests pass, as a clean labelled checklist:

```sh
bash scripts/bounty-tests.sh
```

This runs the host-side suite under the hood and prints each of the seven
required tests as `PASS` (green) with a plain-English description, then
`7/7 bounty-required tests passed`, then the raw `cargo` result lines. It's
much easier to read on camera than the raw output. If you'd rather show the
real thing, `cargo test --workspace --exclude proof-host` is what it wraps.

Then the `RISC0_DEV_MODE=0` proof shot. This binary prints the env banner,
generates a real RISC0 STARK proof, and verifies it:

```sh
RISC0_DEV_MODE=0 ./target/release/bench_post_proof \
  programs/post_proof/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/post_proof.bin
```

Let the camera catch the `RISC0_DEV_MODE = '0'` banner, `prove() OK`, the cycle
count, and `verify() OK`.

Narrate this honestly so it holds up under follow-up questions. Say something
like: "This is the closest thing to a literal `RISC0_DEV_MODE=0` proof, and it
shows real RISC0 proving works end to end in this repo. This particular guest
is the original RISC0 membership post-proof. We later moved the live membership
proof to Groth16 to hit the sub-10-second target (ADR-010 and `cu-costs.md`),
so in production the post-proof is Groth16 and `RISC0_DEV_MODE` governs the
RISC0 chain guests (register and slash)." Don't claim this bench is the live
post-proof path.

Then show the sequencer's env, so the audience sees the chain runs with no
dev-mode shortcuts:

```sh
ps aux | grep sequencer_service | grep -o 'RISC0_DEV_MODE=[01]'
```

Accuracy note: in standalone mode the sequencer *executes* each chain guest
(the `seq.log` "execution time" lines, milliseconds) with `RISC0_DEV_MODE=0`,
i.e. no dev-mode receipts. Frame it as "no dev-mode shortcuts," not "a multi-
second STARK proof per transaction" — the heavy STARK proving is what the
bench above demonstrates, and the membership proof is Groth16 (sub-10s).

## Segment 4 — Full lifecycle, end to end (3 to 4 min, terminal — the centerpiece)

**Say this (read aloud):**

> alright this is the main event, the full lifecycle end to end. on the left
> im tailing the sequencer log so you can watch the chain actually do work, and
> on the right im gonna run the demo. *(run `just demo`)*
>
> ok so watch it go. first it creates a forum instance and registers a member,
> and you can see the stake gets locked in. then it posts anonymously, the
> membership proof gets generated and the post goes out. it posts three times
> in the same window, and notice they share a nullifier but each one carries a
> different shamir share, so an observer cant link them, but those identity
> pieces are quietly being collected. then the moderators sign their N-of-M
> certificates against those posts. then the slasher gathers the K
> certificates, reconstructs the members secret out of the shares, and submits
> one slash transaction, theres the tx hash. and the member is now revoked. and
> because the secret is out, any future post from them gets rejected, which is
> that last test. and there it is, FULL LIFECYCLE OK.

Stage directions / talking points:

In one pane, tail the sequencer so the audience sees it execute each chain tx:

```sh
tail -f ~/seq.log
```

In the other pane, run the demo:

```sh
NWAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<peerId> just demo
```

Narrate each line as it prints:
- create forum instance, register a member (stake locked; watch seq.log execute
  the register guest).
- post anonymously: a membership proof is generated, the post publishes. Three
  posts in one epoch share a nullifier but carry distinct Shamir shares, so
  they're unlinkable to observers yet reconstructable once K certs exist.
- moderators sign N-of-M certificates against the posts.
- the slasher gathers K certs by nullifier, reconstructs the secret, and submits
  one slash transaction. Read out the slash tx hash. The member is revoked.
- close the loop on post rejection: a revoked member's nullifier now matches the
  published revoked-secret, so their future posts are rejected (the
  `post_rejection_after_revocation` test is this property).

End on `FULL LIFECYCLE OK`.

## Segment 5 — Live on the testnet (1 to 2 min, terminal)

**Say this (read aloud):**

> and this isnt just running on my machine, its live on the LEZ testnet. the
> bounty wants two forum instances with different parameters, so heres my
> deployments doc. one deployed program, and two instances under it. instance A
> is K=3 with a 2-of-3 moderator quorum, instance B is K=2 with 3-of-4. let me
> pull one straight off the testnet. *(run the `wallet account get`)* you can
> see the state, the config with those exact parameters baked in, and
> next_leaf_index showing a member already registered with stake. so thats two
> live instances, different K and different N-of-M, on a verified program id.

Stage directions / talking points:

Show the two live instances, with different K and N-of-M, on one deployed
program. Open `docs/deployments.md` to the table, then read one instance live:

```sh
NSSA_WALLET_HOME_DIR=~/wallet-testnet \
  wallet account get -a Public/29HtgrSfYa4AYy6GtysvdxtfNq3THZ2LudouXMRbPQre -r
```

Point out: program ID `4766fcc2...`, Instance A is K=3 / 2-of-3, Instance B is
K=2 / 3-of-4, and `next_leaf_index` shows a member registered with stake. This
is the "two live instances with different parameters and verified program IDs"
criterion.

Optional, for the "non-technical user" angle: switch to the Basecamp app at
`http://localhost:3000` and click the four panels (Forum, Identity, Post,
Feed & moderation) to show the same lifecycle without a CLI.

## Segment 6 — Wrap (30s)

**Say this (read aloud):**

> so thats the whole thing. quick recap, you get anonymous unlinkable posting,
> N-of-M moderation, K-strike slashing that unmasks and bans, instances you can
> parameterize however you want, a reusable forum-agnostic library, an app that
> uses it without modifying it, an IDL through SPEL, and two live instances on
> testnet. the repo is MIT, the whole flow is reproducible with just demo, and
> the full protocol writeup and threat model are in the protocol doc. thanks
> for watching.

Stage directions / talking points:

- Recap against the criteria: anonymous unlinkable posting, N-of-M moderation,
  K-strike slash with retroactive deanonymization, parameterizable instances,
  a forum-agnostic SDK, an app that uses it unmodified, an IDL via SPEL, two
  live testnet instances, and documented CU costs.
- Mention the repo is MIT, the demo is reproducible with `just demo`, and the
  protocol spec and threat model live in `docs/protocol.md`.

## If a step misbehaves on the day

- Daemon or nwaku down: `scripts/demo.mjs` fails fast and tells you where to
  look. Bring the stack back up per `docs/deployments.md` "Restarting the local
  chain", re-confirm `/v1/health`, retry.
- `just` not present on the host: run `node scripts/demo.mjs` directly with the
  same `NWAKU_PEER` / `DAEMON_URL` env.
- Get the nwaku peer id from `curl -s http://127.0.0.1:8645/debug/v1/info` and
  use the `/ws` multiaddr.
