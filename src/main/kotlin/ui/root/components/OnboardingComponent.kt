package io.github.garyttierney.ghidralite.ui.main.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import ghidra.framework.model.DomainFolder
import ghidra.framework.model.Project
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor
import io.github.garyttierney.ghidralite.GhidraWorkerContext
import io.github.garyttierney.ghidralite.framework.GhidraliteProjectManager
import io.github.garyttierney.ghidralite.ui.root.Workspace
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*

@Composable
fun Onboarding(onOnboardingComplete: (Workspace) -> Unit) {
    var showFilePicker by remember { mutableStateOf(false) }

    val projectLoadScope = rememberCoroutineScope()
    var project by remember { mutableStateOf<Project?>(null) }

    LaunchedEffect("project") {
        project = loadProject()
    }

    val files by remember {
        derivedStateOf {
            fun DomainFolder.dirsRecursive(): Sequence<DomainFolder> = sequence {
                yield(this@dirsRecursive)

                for (folder in folders) {
                    yieldAll(folder.dirsRecursive())
                }
            }

            project!!.projectData.rootFolder.dirsRecursive().flatMap { dir -> dir.files.asSequence() }
                .filter { file -> file.contentType == "Program" }
        }
    }

    Box(
        modifier = Modifier.fillMaxSize().background(JewelTheme.globalColors.paneBackground),
        contentAlignment = Alignment.Center
    ) {
        if (project == null) {
            DefaultButton(onClick = { showFilePicker = true }) {
                Text("Select project (.gpr) file ")
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                modifier = Modifier.border(1.dp, JewelTheme.globalColors.borders.normal).width(360.dp),
            ) {
                for (file in files) {
                    item(key = file.fileID) {
                        Row(modifier = Modifier.padding(vertical = 8.dp)) {
                            Text(file.name, modifier = Modifier.weight(1f))

                            DefaultButton(
                                onClick = {
                                    projectLoadScope.launch {
                                        val workspace = withContext(Dispatchers.IO) {
                                            val program = file.getDomainObject(
                                                GhidraWorkerContext,
                                                false,
                                                false,
                                                TaskMonitor.DUMMY
                                            )

                                            Workspace.load(project!!, program as ProgramDB)
                                        }

                                        onOnboardingComplete(workspace)

                                    }
                                }) {
                                Text("Open")
                            }
                        }
                    }
                }
            }
        }
    }
}

suspend fun loadProject(): Project = withContext(GhidraWorkerContext) {
    val projectManager = GhidraliteProjectManager()
    val lastProject = projectManager.recentProjects[0]
    val project = projectManager.openProject(lastProject, false, false)

    project
}

