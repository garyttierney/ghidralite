package io.github.garyttierney.ghidralite.ui.root

import ghidra.app.events.ProgramActivatedPluginEvent
import ghidra.app.util.viewer.format.FormatManager
import ghidra.app.util.viewer.listingpanel.ListingPanel
import ghidra.framework.model.EventType
import ghidra.framework.model.Project
import ghidra.framework.options.ToolOptions
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramEvent
import io.github.garyttierney.ghidralite.GhidraWorkerScope
import io.github.garyttierney.ghidralite.framework.GhidralitePluginTool
import io.github.garyttierney.ghidralite.framework.db.SymbolRecord
import io.github.garyttierney.ghidralite.framework.db.SymbolDbTable
import io.github.garyttierney.ghidralite.framework.search.index.program.ProgramChangeSnapshotStrategy
import io.github.garyttierney.ghidralite.framework.search.index.program.ProgramChangeWatcher
import io.github.garyttierney.ghidralite.framework.search.index.program.ProgramDbTableLoader
import io.github.garyttierney.ghidralite.framework.search.index.program.programChangeInterest
import io.github.garyttierney.ghidralite.framework.search.index.Indexes

object SymbolSnapshotStrategy : ProgramChangeSnapshotStrategy<SymbolRecord> {
    override fun snapshot(event: EventType, old: Any, new: Any): SymbolRecord {
        return when (event) {
            ProgramEvent.SYMBOL_ADDED -> new as SymbolRecord
            ProgramEvent.SYMBOL_RENAMED -> new as SymbolRecord
            else -> throw Exception("Unreachable")
        }
    }
}

class Workspace(val project: Project, val program: Program, val indexes: Indexes) {
    val tool = GhidralitePluginTool(project)
    val listing = ListingPanel(FormatManager(ToolOptions("unused"), ToolOptions("Listing Fields")), program)

    init {
        tool.firePluginEvent(ProgramActivatedPluginEvent("Workspace", program))
    }

    companion object {
        suspend fun load(project: Project, program: ProgramDB): Workspace {
            val indexes = Indexes(GhidraWorkerScope)

            val changeWatcher = ProgramChangeWatcher(GhidraWorkerScope)
            program.addListener(changeWatcher)

            val symbolChanges = changeWatcher.registerInterest(
                programChangeInterest(
                    SymbolSnapshotStrategy,
                    ProgramEvent.SYMBOL_ADDED,
                    ProgramEvent.SYMBOL_RENAMED,
                )
            )
            val symbolDbTable = SymbolDbTable(program.dbHandle.getTable("Symbols"))
            val symbolLoader = ProgramDbTableLoader(symbolDbTable)

            indexes.registerAndLoad(symbolChanges, symbolLoader)

            return Workspace(project, program, indexes)
        }
    }
}