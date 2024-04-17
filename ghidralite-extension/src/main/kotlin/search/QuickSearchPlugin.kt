package io.github.garyttierney.ghidralite.extension.search

import ghidra.app.events.ProgramActivatedPluginEvent
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.services.CodeViewerService
import ghidra.app.services.GoToService
import ghidra.app.services.ProgramManager
import ghidra.app.util.viewer.listingpanel.ListingPanel
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.Program
import ghidra.program.util.ChangeManager
import ghidra.util.task.MonitoredRunnable
import ghidra.util.task.TaskLauncher
import io.github.garyttierney.ghidralite.core.db.SymbolDbTable
import io.github.garyttierney.ghidralite.core.db.SymbolRecord
import io.github.garyttierney.ghidralite.core.search.SearchResult
import io.github.garyttierney.ghidralite.core.search.Searcher
import io.github.garyttierney.ghidralite.core.search.index.IndexWriter
import io.github.garyttierney.ghidralite.core.search.index.Indexes
import io.github.garyttierney.ghidralite.core.search.index.program.ProgramChangeWatcher
import io.github.garyttierney.ghidralite.core.search.index.program.programChangeInterest
import io.github.garyttierney.ghidralite.core.search.index.program.symbol.SymbolIndexLoader
import io.github.garyttierney.ghidralite.core.search.index.program.symbol.SymbolSnapshotStrategy
import io.github.garyttierney.ghidralite.extension.GhidralitePluginPackage
import kotlinx.coroutines.*
import org.apache.logging.log4j.LogManager.getLogger

@ghidra.framework.plugintool.PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = GhidralitePluginPackage.NAME,
    category = PluginCategoryNames.NAVIGATION,
    shortDescription = "Quick Search",
    description = "Quick Search for Symbols",
    servicesRequired = [ProgramManager::class, CodeViewerService::class],
    servicesProvided = [QuickSearchService::class],
    eventsConsumed = [ProgramActivatedPluginEvent::class]
)
class QuickSearchPlugin(tool: PluginTool) : ProgramPlugin(tool), QuickSearchService {
    private val logger = getLogger(QuickSearchPlugin::class.java)
    private val coroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val indexes = Indexes()
    private val searcher = Searcher(indexes)

    private lateinit var goToService: GoToService
    private lateinit var codeViewerService: CodeViewerService
    private lateinit var previewListing: ListingPanel

    override fun init() {
        goToService = tool.getService(GoToService::class.java)
        codeViewerService = tool.getService(CodeViewerService::class.java)
        previewListing = codeViewerService.listingPanel

        tool.toolActions.addGlobalAction(QuickSearchAction(this, previewListing, goToService))
    }

    override fun programActivated(program: Program) {
        previewListing.program = program

        val changeWatcher = ProgramChangeWatcher(coroutineScope)
        program.addListener(changeWatcher)

        val symbolChanges = changeWatcher.registerInterest(
            programChangeInterest(
                SymbolSnapshotStrategy,
                ChangeManager.DOCR_SYMBOL_ADDED,
                ChangeManager.DOCR_SYMBOL_RENAMED,
            )
        )

        program as ProgramDB

        val symbolDbTable = SymbolDbTable(program.dbHandle.getTable("Symbols"))
        val symbolIndexLoader = SymbolIndexLoader(symbolDbTable)
        val symbolIndexWriter = IndexWriter(indexes, SymbolRecord::class)

        TaskLauncher.launchModal("Indexing Program", MonitoredRunnable {
            it.message = "Indexing Symbols"

            try {
                runBlocking {
                    indexes.load(symbolIndexLoader)
                }

                coroutineScope.launch {
                    symbolIndexWriter.run(symbolChanges)
                }
            } catch (e: Exception) {
                logger.error("Failed to index program", e)
            }
        })
    }

    override suspend fun search(query: String, onResultAvailable: (List<SearchResult>) -> Unit) =
        searcher.query(query, onResultAvailable)
}