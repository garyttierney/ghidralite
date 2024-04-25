package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.statusBar.widgets

import androidx.compose.runtime.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import org.jetbrains.jewel.ui.component.*
import java.lang.management.ManagementFactory
import javax.management.ObjectName
import kotlin.time.Duration.Companion.seconds


@Composable
fun ResourceConsumption() {
    var cpuUsage by remember { mutableStateOf(0.00) }
    var usedMemoryMb by remember { mutableStateOf(0L) }
    var totalMemoryMb by remember { mutableStateOf(0L) }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.Default) {
            val mbeanServer = ManagementFactory.getPlatformMBeanServer()
            val osObject = ObjectName("java.lang:type=OperatingSystem")

            while (isActive) {
                val cpuLoad = mbeanServer.getAttribute(osObject, "ProcessCpuLoad")

                totalMemoryMb = Runtime.getRuntime().totalMemory() / 1024 / 1024
                usedMemoryMb = totalMemoryMb - Runtime.getRuntime().freeMemory() / 1024 / 1024
                cpuUsage = cpuLoad as Double

                delay(1.seconds)
            }
        }
    }

    Text("CPU: ${"%.2f".format(cpuUsage)}%")
    Text("RAM: $usedMemoryMb/$totalMemoryMb MB")
}