package io.github.garyttierney.ghidralite.framework

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin
import ghidra.framework.model.Project
import ghidra.framework.plugintool.PluginTool

class GhidralitePluginTool(project: Project) : PluginTool(project, "Ghidralite", false, true, false) {
    init {
        addPlugin(CodeBrowserPlugin(this))
    }
}