package io.github.garyttierney.ghidralite.core.project

import ghidra.framework.model.DomainFile
import ghidra.framework.model.DomainFolder
import ghidra.framework.store.FolderItem

fun DomainFolder.walk() = sequence<DomainFile> {
    val queue = ArrayDeque(listOf(this@walk))

    while (queue.isNotEmpty()) {
        val folder = queue.removeFirst()

        for (file in folder.files) {
            yield(file)
        }

        queue.addAll(folder.folders)
    }
}