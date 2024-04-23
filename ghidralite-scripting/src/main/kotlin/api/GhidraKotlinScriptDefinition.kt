package io.github.garyttierney.ghidralite.scripting.api

import io.github.garyttierney.ghidralite.scripting.host.GhidraScriptCompilationConfiguration
import kotlin.script.experimental.annotations.KotlinScript

const val GHIDRA_KOTLIN_SCRIPT_EXTENSION = "ghidra.kts"

@KotlinScript(
    fileExtension = GHIDRA_KOTLIN_SCRIPT_EXTENSION,
    compilationConfiguration = GhidraScriptCompilationConfiguration::class,
)
open class GhidraKotlinScriptDefinition