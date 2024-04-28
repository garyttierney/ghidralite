package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.statusBar.widgets

import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.standalone.app.task.ApplicationTaskProgress
import io.github.garyttierney.ghidralite.standalone.app.task.LocalApplicationTaskRunner
import org.jetbrains.jewel.ui.component.*


@Composable
fun TaskProgress() {
    val firstTask = LocalApplicationTaskRunner.current.tasks.firstOrNull()
    val progressBarModifier = Modifier.width(64.dp)

    if (firstTask != null) {
        Text(firstTask.progress.message)

        when (val progress = firstTask.progress) {
            is ApplicationTaskProgress.Indeterminate -> IndeterminateHorizontalProgressBar(modifier = progressBarModifier)
            is ApplicationTaskProgress.Progress -> HorizontalProgressBar(
                progress.total / progress.current.toFloat(),
                modifier = progressBarModifier
            )
        }
    }
}