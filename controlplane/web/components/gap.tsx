const GAPS = [
  {
    title: "Publish-time scanners",
    body: "scan a skill once, when it's published. Nothing checks what's actually on your machine afterward.",
    isGap: false,
  },
  {
    title: "Enterprise cloud gateways",
    body: "expensive, demo-gated, built for security orgs. Nothing sized for a solo dev or a 5-person team.",
    isGap: false,
  },
  {
    title: "Your machine, right now",
    body: "no inventory, no lockfile, no tamper detection, no egress control. Eyebrow lives here.",
    isGap: true,
  },
]

export function Gap() {
  return (
    <section className="border-b border-border bg-card">
      <div className="mx-auto max-w-[1100px] px-6 py-20">
        <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-3">
          {GAPS.map((item) => (
            <div
              key={item.title}
              className={`bg-card p-6 ${item.isGap ? "ring-1 ring-inset ring-primary/40" : ""}`}
            >
              <h3 className="flex items-center gap-2 font-mono text-sm font-semibold text-foreground">
                {item.title}
                {item.isGap && (
                  <span className="rounded border border-primary/40 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-primary">
                    the gap
                  </span>
                )}
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{item.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
