package io.github.garyttierney.ghidralite.scripting.host

import io.github.garyttierney.ghidralite.scripting.api.GhidraKotlinScriptDefinition
import io.github.garyttierney.ghidralite.scripting.integration.KotlinScript
import kotlin.script.experimental.api.*
import kotlin.script.experimental.jvm.dependenciesFromClassContext
import kotlin.script.experimental.jvm.jvm

class GhidraScriptCompilationConfiguration : ScriptCompilationConfiguration({
    implicitReceivers(KotlinScript::class)

    jvm {
        dependenciesFromClassContext(
            GhidraKotlinScriptDefinition::class,
            wholeClasspath = true,
            libraries = arrayOf("kotlin-stdlib", "kotlin-reflect")
        )
    }

    ide {
        acceptedLocations(ScriptAcceptedLocation.Everywhere)
    }
})