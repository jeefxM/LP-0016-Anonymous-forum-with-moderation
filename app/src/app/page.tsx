"use client";

import { useMemo, useState } from "react";
import { SdkProvider, useSdk, type FeedPost } from "@/components/SdkProvider";
import { DAEMON_URL, K_THRESHOLD, N_THRESHOLD, short, WAKU_PEER } from "@/lib/forum";

export default function Page() {
  return (
    <SdkProvider>
      <Dashboard />
    </SdkProvider>
  );
}

const card: React.CSSProperties = {
  border: "1px solid #232830",
  borderRadius: 10,
  padding: 20,
  marginBottom: 16,
  background: "#11151b",
};
const btn: React.CSSProperties = {
  background: "#3b82f6",
  color: "white",
  border: "none",
  borderRadius: 8,
  padding: "8px 14px",
  cursor: "pointer",
  fontSize: 14,
};
const mono: React.CSSProperties = { fontFamily: "ui-monospace, monospace", fontSize: 12, color: "#9aa4b2" };

function Dashboard() {
  const sdk = useSdk();
  return (
    <main style={{ maxWidth: 860, margin: "0 auto", padding: 24 }}>
      <header style={{ marginBottom: 8 }}>
        <h1 style={{ margin: 0 }}>Basecamp</h1>
        <p style={{ ...mono, marginTop: 4 }}>
          Anonymous forum · {N_THRESHOLD}-of-3 moderation · {K_THRESHOLD}-strike revocation · LP-0016
        </p>
      </header>

      <StoreBanner />

      {sdk.busy && (
        <div style={{ ...card, background: "#1a2230", borderColor: "#2c4a7a" }}>
          <strong>⏳ {sdk.busy}…</strong>
        </div>
      )}
      {sdk.error && (
        <div style={{ ...card, background: "#2a1416", borderColor: "#7a2c2c" }}>
          <strong style={{ color: "#ff8a8a" }}>Error:</strong> <span style={mono}>{sdk.error}</span>
        </div>
      )}

      <ConnectPanel />
      {sdk.forum && <MemberPanel />}
      {sdk.forum && sdk.identity && <ComposePanel />}
      {sdk.forum && <Feed />}
    </main>
  );
}

function StoreBanner() {
  return (
    <div style={{ ...card, background: "#15130c", borderColor: "#5a4a1a" }}>
      <span style={{ fontSize: 13 }}>
        ⚠️ Posts and certificates live on Waku and are only retrievable within the node&apos;s Store
        retention window. Older content may be unavailable; trees fall back to a trusted snapshot (ADR-001).
      </span>
    </div>
  );
}

function ConnectPanel() {
  const sdk = useSdk();
  return (
    <section style={card}>
      <h2 style={{ marginTop: 0 }}>1 · Forum</h2>
      <p style={mono}>
        daemon {DAEMON_URL} · waku {WAKU_PEER ? short(WAKU_PEER.split("/p2p/")[1] ?? WAKU_PEER, 6) : "(unset)"}
      </p>
      {!sdk.forum ? (
        <button style={btn} disabled={sdk.status === "connecting"} onClick={() => sdk.createForum()}>
          {sdk.status === "connecting" ? "Connecting…" : "Create demo forum"}
        </button>
      ) : (
        <div style={mono}>
          <div>forumId: {sdk.forum.forumId}</div>
          <div>root: {short(sdk.forum.treeRoot)}</div>
          <div>members: {sdk.forum.nextLeafIndex}</div>
          <div style={{ color: "#5fd07a" }}>status: ready ✅</div>
        </div>
      )}
    </section>
  );
}

function MemberPanel() {
  const sdk = useSdk();
  const revoked = sdk.identity ? sdk.revoked.has(sdk.identity.commitment) : false;
  return (
    <section style={card}>
      <h2 style={{ marginTop: 0 }}>2 · Member</h2>
      {!sdk.identity ? (
        <button style={btn} onClick={() => sdk.joinIdentity()}>
          Create identity & join
        </button>
      ) : (
        <div style={mono}>
          <div>commitment: {short(sdk.identity.commitment)}</div>
          <div>leaf index: {sdk.leafIndex}</div>
          <div style={{ color: revoked ? "#ff8a8a" : "#5fd07a" }}>
            {revoked ? "REVOKED ❌ (slashed)" : "active member ✅"}
          </div>
        </div>
      )}
    </section>
  );
}

function ComposePanel() {
  const sdk = useSdk();
  const [text, setText] = useState("");
  const [epoch, setEpoch] = useState(1);
  const disabled = !!sdk.busy || !text.trim();
  return (
    <section style={card}>
      <h2 style={{ marginTop: 0 }}>3 · Post anonymously</h2>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Write something… membership is proven in zero knowledge."
        rows={3}
        style={{ width: "100%", boxSizing: "border-box", background: "#0b0d10", color: "#e6e8eb", border: "1px solid #232830", borderRadius: 8, padding: 10, fontSize: 14 }}
      />
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 8 }}>
        <label style={mono}>
          epoch{" "}
          <input
            type="number"
            value={epoch}
            min={1}
            onChange={(e) => setEpoch(Number(e.target.value))}
            style={{ width: 56, background: "#0b0d10", color: "#e6e8eb", border: "1px solid #232830", borderRadius: 6, padding: 4 }}
          />
        </label>
        <button
          style={{ ...btn, opacity: disabled ? 0.5 : 1 }}
          disabled={disabled}
          onClick={async () => {
            await sdk.composePost(text, epoch);
            setText("");
          }}
        >
          Prove & post
        </button>
        {sdk.lastProofMs != null && (
          <span style={{ ...mono, color: sdk.lastProofMs < 10000 ? "#5fd07a" : "#ffae5f" }}>
            last proof: {(sdk.lastProofMs / 1000).toFixed(2)}s {sdk.lastProofMs < 10000 ? "(< 10s ✅)" : ""}
          </span>
        )}
      </div>
      <p style={{ ...mono, marginBottom: 0 }}>
        Same epoch ⇒ same nullifier (posts linkable within an epoch); distinct epochs are unlinkable.
      </p>
    </section>
  );
}

function Feed() {
  const sdk = useSdk();
  // Group strike progress per nullifier for the moderator slash control.
  const nullifiers = useMemo(() => {
    const set = new Map<string, number>();
    for (const p of sdk.posts) set.set(p.envelope.nullifier, (set.get(p.envelope.nullifier) ?? 0) + 1);
    return [...set.keys()];
  }, [sdk.posts]);

  return (
    <section style={card}>
      <h2 style={{ marginTop: 0 }}>4 · Feed &amp; moderation</h2>
      {sdk.posts.length === 0 && <p style={mono}>No posts yet.</p>}
      {sdk.posts.map((p) => (
        <PostRow key={`${p.envelope.nullifier}:${p.envelope.contentId}`} post={p} />
      ))}

      {nullifiers.length > 0 && (
        <div style={{ marginTop: 16, borderTop: "1px solid #232830", paddingTop: 12 }}>
          <h3 style={{ margin: "0 0 8px" }}>Members under strike</h3>
          {nullifiers.map((n) => {
            const strikes = sdk.strikesByNullifier[n] ?? 0;
            const canSlash = strikes >= K_THRESHOLD;
            return (
              <div key={n} style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 6 }}>
                <span style={mono}>nullifier {short(n)}</span>
                <span style={mono}>
                  {strikes}/{K_THRESHOLD} strikes
                </span>
                <button
                  style={{ ...btn, background: canSlash ? "#dc2626" : "#3a3f47", opacity: sdk.busy ? 0.5 : 1 }}
                  disabled={!canSlash || !!sdk.busy}
                  onClick={() => sdk.slashMember(n)}
                >
                  Reconstruct &amp; slash
                </button>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

function PostRow({ post }: { post: FeedPost }) {
  const sdk = useSdk();
  const badge =
    post.verified === null ? (
      <span style={{ ...mono, color: "#ffae5f" }}>verifying…</span>
    ) : post.verified ? (
      <span style={{ ...mono, color: "#5fd07a" }}>member ✅</span>
    ) : (
      <span style={{ ...mono, color: "#ff8a8a" }}>invalid ❌</span>
    );
  return (
    <div style={{ borderTop: "1px solid #1b2027", padding: "10px 0" }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
        <span>{post.text ?? <span style={mono}>content {short(post.envelope.contentId)}</span>}</span>
        {badge}
      </div>
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 4 }}>
        <span style={mono}>nullifier {short(post.envelope.nullifier)}</span>
        {post.struck ? (
          <span style={{ ...mono, color: "#ffae5f" }}>struck</span>
        ) : (
          <button
            style={{ ...btn, padding: "4px 10px", fontSize: 12, background: "#7a5c1a", opacity: sdk.busy ? 0.5 : 1 }}
            disabled={!!sdk.busy}
            onClick={() => sdk.strike(post.envelope)}
          >
            Strike ({N_THRESHOLD}-of-3)
          </button>
        )}
      </div>
    </div>
  );
}
