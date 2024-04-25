package io.github.garyttierney.ghidralite.standalone.app.task

interface ApplicationTaskScope {
    fun taskMessage(message: String)

    fun taskProgress(message: String, current: Int, total: Int)
}