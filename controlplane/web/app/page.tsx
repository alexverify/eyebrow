import type { Metadata } from "next"
import { DashboardHeader } from "@/components/dashboard/dashboard-header"
import { Dashboard } from "@/components/dashboard/dashboard"

export const metadata: Metadata = {
  title: "Assay — Local Scan Dashboard",
  description:
    "Inventory, lockfile, security findings, and rug-pull drift detection for the skills, MCP servers, and plugins installed in your AI coding agents.",
}

export default function Page() {
  return (
    <>
      <DashboardHeader />
      <main>
        <Dashboard />
      </main>
    </>
  )
}
