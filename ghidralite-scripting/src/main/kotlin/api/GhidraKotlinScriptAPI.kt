package io.github.garyttierney.ghidralite.scripting.api

import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection
import ghidra.program.model.listing.Function

interface GhidraKotlinScriptAPI {
    var currentFunction: Function
    var currentHighlight: ProgramSelection
    var currentLocation: ProgramLocation
    var currentSelection: ProgramSelection
    val program: Program
}