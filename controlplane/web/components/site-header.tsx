import { GithubIcon } from "@/components/github-icon"
import { ThemeToggle } from "@/components/theme-toggle"

export function SiteHeader() {
  return (
    <header className="border-b border-border">
      <div className="mx-auto flex max-w-[1100px] items-center justify-between px-6 py-4">
        <a href="#" className="font-mono text-sm font-semibold tracking-tight text-foreground">
          Assay
        </a>
        <nav className="flex items-center gap-6 font-mono text-xs text-muted-foreground">
          <a href="#docs" className="transition-colors hover:text-foreground">
            Docs
          </a>
          <a href="#team" className="transition-colors hover:text-foreground">
            Team
          </a>
          <a
            href="https://github.com/alexverify/assay"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 transition-colors hover:text-foreground"
          >
            <GithubIcon className="h-4 w-4" />
            GitHub
          </a>
          <ThemeToggle />
        </nav>
      </div>
    </header>
  )
}
