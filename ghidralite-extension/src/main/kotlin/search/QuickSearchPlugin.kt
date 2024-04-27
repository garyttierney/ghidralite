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
import ghidra.program.model.symbol.Symbol
import ghidra.program.util.ChangeManager
import ghidra.util.task.MonitoredRunnable
import ghidra.util.task.TaskLauncher
import io.github.garyttierney.ghidralite.core.db.SymbolDbTable
import io.github.garyttierney.ghidralite.core.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.core.index.EntityIndexer
import io.github.garyttierney.ghidralite.core.index.storage.InMemoryIndex
import io.github.garyttierney.ghidralite.core.search.SearchResult
import io.github.garyttierney.ghidralite.core.search.Searcher
import io.github.garyttierney.ghidralite.core.index.program.ProgramChangeWatcher
import io.github.garyttierney.ghidralite.core.search.index.program.symbol.SymbolIndexLoader
import io.github.garyttierney.ghidralite.core.search.symbol.SymbolProvider
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
    private val symbolIndex = InMemoryIndex<Long, SymbolLookupDetails>()
    private val searcher = Searcher(symbolIndex)

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

        val programChangeWatcher = ProgramChangeWatcher(coroutineScope)
        program.addListener(programChangeWatcher)

        program as ProgramDB

        val symbolDbTable = SymbolDbTable(program.dbHandle.getTable("Symbols"))
        val symbolIndexLoader = SymbolIndexLoader(symbolDbTable)
        val symbolIndexer = EntityIndexer(symbolIndex, SymbolProvider())

        TaskLauncher.launchModal(
            "Indexing Program",
            MonitoredRunnable {
                it.message = "Indexing Symbols"

                try {
                    runBlocking {
                        symbolIndex.load(symbolIndexLoader)
                    }

                    coroutineScope.launch(Dispatchers.IO) {
                        symbolIndexer.index(
                            programChangeWatcher.registerInterest<Symbol>(
                                addedEvent = ChangeManager.DOCR_SYMBOL_ADDED,
                                removedEvent = ChangeManager.DOCR_SYMBOL_REMOVED,
                                ChangeManager.DOCR_SYMBOL_RENAMED,
                                ChangeManager.DOCR_SYMBOL_SCOPE_CHANGED,
                            )
                        )
                    }
                } catch (ignored: Exception) {
                    logger.error("Failed to index program", ignored)
                }
            }
        )
    }

    override suspend fun search(query: String, onResultAvailable: (List<SearchResult>) -> Unit) =
        searcher.query(query, onResultAvailable)
}
