import { CopyCommand } from "@/components/copy-command"
import { GithubIcon } from "@/components/github-icon"

export function FinalCta() {
  return (
    <section className="border-b border-border">
      <div className="mx-auto max-w-[1100px] px-6 py-20 text-center">
        <h2 className="text-balance font-mono text-2xl font-semibold tracking-tight md:text-3xl">
          Find out what&apos;s already installed. It takes seconds.
        </h2>
        <div className="mt-8 flex flex-col items-center gap-4">
          <CopyCommand />
          <a
            href="https://github.com/alexverify/assay"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-md border border-border bg-transparent px-4 py-2.5 font-mono text-sm text-foreground transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            <GithubIcon className="h-4 w-4" />
            View on GitHub
          </a>
        </div>
      </div>
    </section>
  )
}
