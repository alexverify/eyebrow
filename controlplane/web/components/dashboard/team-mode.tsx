"use client"

import { createContext, useContext } from "react"

// TeamModeContext is true when the user has opted into shared, signature-verified
// trust (a trusted-keys registry exists). When false (solo), the UI hides the
// signed/unsigned/verified vocabulary and shows plain Approved / Not approved.
export const TeamModeContext = createContext(false)

export const useTeamMode = () => useContext(TeamModeContext)
