import type { ReactNode } from "react"

function CodeBlock({ children }: { children: ReactNode }) {
  return (
    <pre className="mt-5 overflow-x-auto rounded-md border border-border bg-background px-4 py-3 font-mono text-[13px] leading-6">
      <code>{children}</code>
    </pre>
  )
}

export function Solution() {
  return (
    <section className="border-b border-border">
      <div className="mx-auto max-w-[1100px] px-6 py-20">
        <h2 className="text-balance font-mono text-2xl font-semibold tracking-tight md:text-3xl">
          Audit, lock, and gate everything your agent runs.
        </h2>

        <div className="mt-12 grid gap-10 lg:grid-cols-3">
          <div>
            <h3 className="font-mono text-base font-semibold text-foreground">Inventory &amp; audit</h3>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              One command inventories every skill, MCP server, and plugin installed across Claude Code, Cursor, Codex,
              and OpenCode, and flags known injection and exfiltration patterns.
            </p>
            <CodeBlock>
              <span className="text-muted-foreground">$ </span>
              <span className="text-card-foreground">npx assay audit</span>
            </CodeBlock>
          </div>

          <div>
            <h3 className="font-mono text-base font-semibold text-foreground">Lockfile &amp; rug-pull detection</h3>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              A committed lockfile pins content hashes for everything installed. If a skill changes on disk after you
              audited it, Assay tells you before your agent runs it.
            </p>
            <CodeBlock>
              <span className="text-muted-foreground">{"# assay.lock"}</span>
              {"\n"}
              <span className="text-card-foreground">{'web-fetch-pro = "3.2.1"'}</span>
              {"\n"}
              <span className="text-muted-foreground">{"  sha256 = "}</span>
              <span className="text-card-foreground">{'"c80a…1d44"'}</span>
            </CodeBlock>
          </div>

          <div>
            <h3 className="font-mono text-base font-semibold text-foreground">Runtime firewall &amp; CI gate</h3>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Declarative policy for domain and filesystem allowlists, secret redaction at the proxy layer, and a GitHub
              Action that fails the build on unsigned or drifted skills.
            </p>
            <CodeBlock>
              <span className="text-card-foreground">{"policy:"}</span>
              {"\n"}
              <span className="text-card-foreground">{"  allow_domains: [api.github.com]"}</span>
              {"\n"}
              <span className="text-card-foreground">{"  block_paths:   [~/.ssh, ./.env]"}</span>
              {"\n"}
              <span className="text-card-foreground">{"  on_drift:      fail"}</span>
            </CodeBlock>
          </div>
        </div>
      </div>
    </section>
  )
}
