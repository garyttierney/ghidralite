package io.github.garyttierney.ghidralite.scripting.host

import io.github.garyttierney.ghidralite.scripting.integration.KotlinScript
import kotlin.script.experimental.api.ScriptEvaluationConfiguration
import kotlin.script.experimental.api.implicitReceivers

class GhidraScriptEvaluationConfiguration(api: KotlinScript) : ScriptEvaluationConfiguration({
    implicitReceivers(api)
})