package io.github.garyttierney.ghidralite.scripting.integration

import ghidra.app.script.GhidraScript
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection
import io.github.garyttierney.ghidralite.scripting.api.GhidraKotlinScriptAPI
import io.github.garyttierney.ghidralite.scripting.api.GhidraKotlinScriptDefinition
import io.github.garyttierney.ghidralite.scripting.host.GhidraScriptEvaluationConfiguration
import java.io.BufferedReader
import kotlin.script.experimental.host.toScriptSource
import kotlin.script.experimental.jvm.util.isError
import kotlin.script.experimental.jvm.util.isIncomplete
import kotlin.script.experimental.jvmhost.BasicJvmScriptingHost
import kotlin.script.experimental.jvmhost.createJvmCompilationConfigurationFromTemplate

class KotlinScript(private val host: BasicJvmScriptingHost) : GhidraScript(), GhidraKotlinScriptAPI {
    override var currentFunction: Function by this::currentFunction
    override var currentHighlight: ProgramSelection by this::currentHighlight
    override var currentLocation: ProgramLocation by this::currentLocation
    override var currentSelection: ProgramSelection by this::currentSelection
    override val program: Program by this::currentProgram

    override fun run() {
        val compileConfiguration = createJvmCompilationConfigurationFromTemplate<GhidraKotlinScriptDefinition>()
        val evaluationConfiguration = GhidraScriptEvaluationConfiguration(this)
        val script = sourceFile.inputStream.bufferedReader().use(BufferedReader::readText)
        val result = host.eval(script.toScriptSource(sourceFile.name), compileConfiguration, evaluationConfiguration)

        if (result.isError() || result.isIncomplete()) {
            result.reports.forEach { printerr(it.message) }
        }
    }
}