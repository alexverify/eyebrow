import Link from "next/link"
import { ShieldCheck } from "lucide-react"
import { GithubIcon } from "@/components/github-icon"
import { ThemeToggle } from "@/components/theme-toggle"

export function DashboardHeader() {
  return (
    <header className="border-b border-border">
      <div className="mx-auto flex max-w-[1200px] items-center justify-between px-6 py-4">
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2 font-mono text-sm font-semibold tracking-tight text-foreground">
            <ShieldCheck className="h-4 w-4 text-primary" />
            Eyebrow
          </Link>
          <nav className="hidden items-center gap-5 font-mono text-xs text-muted-foreground sm:flex">
            <span className="text-foreground">Dashboard</span>
            <Link href="/" className="transition-colors hover:text-foreground">
              Home
            </Link>
          </nav>
        </div>
        <div className="flex items-center gap-5 font-mono text-xs text-muted-foreground">
          <span className="hidden items-center gap-1.5 sm:inline-flex">
            <span className="h-1.5 w-1.5 rounded-full bg-ok" aria-hidden />
            local · this machine
          </span>
          <a
            href="https://github.com/alexverify/eyebrow"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 transition-colors hover:text-foreground"
          >
            <GithubIcon className="h-4 w-4" />
            GitHub
          </a>
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
