package io.github.garyttierney.ghidralite.ui.root

//
//object SymbolSnapshotStrategy : ProgramChangeSnapshotStrategy<SymbolRecord> {
//    override fun snapshot(event: EventType, old: Any, new: Any): SymbolRecord {
//        return when (event) {
//            ProgramEvent.SYMBOL_ADDED -> new as SymbolRecord
//            ProgramEvent.SYMBOL_RENAMED -> new as SymbolRecord
//            else -> throw Exception("Unreachable")
//        }
//    }
//}
//
//class Workspace(val project: Project, val program: Program, val searcher: Searcher) {
//    val tool = GhidralitePluginTool(project)
//    val listing = ListingPanel(FormatManager(ToolOptions("unused"), ToolOptions("Listing Fields")), program)
//
//
//    init {
//        tool.firePluginEvent(ProgramActivatedPluginEvent("Workspace", program))
//    }
//
//    companion object {
//        suspend fun load(project: Project, program: ProgramDB): Workspace {
//            val indexes = Indexes()
//
//            val changeWatcher = ProgramChangeWatcher(GhidraWorkerScope)
//            program.addListener(changeWatcher)
//
//            val symbolChanges = changeWatcher.registerInterest(
//                programChangeInterest(
//                    SymbolSnapshotStrategy,
//                    ProgramEvent.SYMBOL_ADDED,
//                    ProgramEvent.SYMBOL_RENAMED,
//                )
//            )
//            val symbolDbTable = SymbolDbTable(program.dbHandle.getTable("Symbols"))
//            val symbolIndexLoader = SymbolIndexLoader(symbolDbTable)
//            val symbolIndexWriter = IndexWriter(indexes, SymbolRecord::class)
//
//            indexes.load(symbolIndexLoader)
//
//            GhidraWorkerScope.launch {
//                symbolIndexWriter.run(symbolChanges)
//            }
//
//            return Workspace(project, program, Searcher(indexes))
//        }
//    }
//}