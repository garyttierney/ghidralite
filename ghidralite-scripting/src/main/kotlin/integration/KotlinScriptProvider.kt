package io.github.garyttierney.ghidralite.scripting.integration

import generic.jar.ResourceFile
import ghidra.app.script.GhidraScript
import ghidra.app.script.GhidraScriptProvider
import io.github.garyttierney.ghidralite.scripting.api.GHIDRA_KOTLIN_SCRIPT_EXTENSION
import java.io.PrintWriter
import kotlin.script.experimental.jvmhost.BasicJvmScriptingHost

class KotlinScriptProvider : GhidraScriptProvider() {
    private val scriptHost = BasicJvmScriptingHost()

    override fun getDescription(): String {
        return "Kotlin"
    }

    override fun getExtension(): String {
        return ".$GHIDRA_KOTLIN_SCRIPT_EXTENSION"
    }

    override fun getScriptInstance(sourceFile: ResourceFile, writer: PrintWriter): GhidraScript {
        val kotlinScript = KotlinScript(scriptHost)
        kotlinScript.sourceFile = sourceFile

        return kotlinScript
    }

    override fun createNewScript(newScript: ResourceFile, category: String?) {
        val writer = newScript.getFile(false).printWriter()

        writer.use {
            writeHeader(it, category)
            writeBody(it)
        }
    }

    override fun getCommentCharacter(): String {
        return "//"
    }
}