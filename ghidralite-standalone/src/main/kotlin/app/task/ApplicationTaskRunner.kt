package io.github.garyttierney.ghidralite.standalone.app.task

import androidx.compose.runtime.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

val LocalApplicationTaskRunner: ProvidableCompositionLocal<ApplicationTaskRunner> =
    staticCompositionLocalOf {
        error("No ContentColor provided. Have you forgotten the theme?")
    }

val TaskRunner: ApplicationTaskRunner
    @Composable get() = LocalApplicationTaskRunner.current

class ApplicationTaskRunner {
    private val backgroundDispatcher = Executors.newWorkStealingPool().asCoroutineDispatcher()

    val tasks = mutableStateListOf<ApplicationTask>()

    fun run(
        title: String,
        modal: Boolean = false,
        scope: CoroutineScope,
        block: suspend ApplicationTaskScope.() -> Unit
    ) {
        val task = ApplicationTask(modal, ApplicationTaskProgress.Indeterminate(title))
        val job = scope.launch(context = backgroundDispatcher) {
            tasks.add(task)

            try {
                task.block()
            } finally {
                tasks.remove(task)
            }
        }

        task.job = job
    }
}

interface ScopedApplicationTaskRunner {
    fun run(title: String, modal: Boolean = false, block: suspend ApplicationTaskScope.() -> Unit)
}

@Composable
fun rememberTaskRunner(
    scope: CoroutineScope = rememberCoroutineScope(),
    runner: ApplicationTaskRunner = LocalApplicationTaskRunner.current
) = remember {
    object : ScopedApplicationTaskRunner {
        override fun run(title: String, modal: Boolean, block: suspend ApplicationTaskScope.() -> Unit) {
            runner.run(title, modal, scope, block)
        }
    }
}