export function SiteFooter() {
  return (
    <footer>
      <div className="mx-auto flex max-w-[1100px] flex-col gap-4 px-6 py-10 font-mono text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
        <span className="font-semibold text-foreground">Assay</span>
        <nav className="flex items-center gap-6">
          <a
            href="https://github.com/alexverify/assay"
            target="_blank"
            rel="noreferrer"
            className="transition-colors hover:text-foreground"
          >
            GitHub
          </a>
          <a href="#docs" className="transition-colors hover:text-foreground">
            Docs
          </a>
          <a href="#contact" className="transition-colors hover:text-foreground">
            Contact
          </a>
        </nav>
      </div>
    </footer>
  )
}
