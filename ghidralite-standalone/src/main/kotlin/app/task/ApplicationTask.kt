package io.github.garyttierney.ghidralite.standalone.app.task

import kotlinx.coroutines.Job

sealed interface ApplicationTaskProgress {
    val message: String

    data class Indeterminate(override val message: String) : ApplicationTaskProgress
    data class Progress(override val message: String, val current: Int, val total: Int) : ApplicationTaskProgress
}

class ApplicationTask(val isModal: Boolean, var progress: ApplicationTaskProgress) : ApplicationTaskScope {
    lateinit var job: Job

    override fun taskMessage(message: String) {
        progress = ApplicationTaskProgress.Indeterminate(message)
    }

    override fun taskProgress(message: String, current: Int, total: Int) {
        progress = ApplicationTaskProgress.Progress(message, current, total)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ApplicationTask

        return job == other.job
    }

    override fun hashCode(): Int {
        return job.hashCode()
    }
}