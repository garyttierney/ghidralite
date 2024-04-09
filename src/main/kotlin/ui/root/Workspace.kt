package io.github.garyttierney.ghidralite.ui.root

import ghidra.app.events.ProgramActivatedPluginEvent
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService
import ghidra.app.plugin.core.codebrowser.hover.ReferenceListingHover
import ghidra.app.util.viewer.format.FormatManager
import ghidra.app.util.viewer.listingpanel.ListingPanel
import ghidra.framework.model.Project
import ghidra.framework.options.ToolOptions
import ghidra.program.model.listing.Program
import io.github.garyttierney.ghidralite.framework.GhidralitePluginTool

class Workspace(val project: Project, val program: Program) {
    val tool = GhidralitePluginTool(project)
    val listing = ListingPanel(FormatManager(ToolOptions("unused"), ToolOptions("Listing Fields")), program)

    init {
        tool.firePluginEvent(ProgramActivatedPluginEvent("Workspace", program))
    }
}