@file:Suppress("UnstableApiUsage")


plugins {
    `ghidralite-conventions`
    alias(libs.plugins.ksp)
    alias(libs.plugins.kotlinx.serialization)
    alias(libs.plugins.composeDesktop)
}

val ghidraDistribution = extra["ghidra.dir"] as String

dependencies {
    implementation(project(":ghidralite-core-ksp"))
    ksp(project(":ghidralite-core-ksp"))

    implementation(libs.kotlin.reflect)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.filePicker)

    implementation(libs.jewel.standalone)
    implementation(libs.jewel.decorated.window)

    implementation(libs.jetbrains.compose.splitpane)
    implementation(compose.desktop.currentOs) {
        exclude(group = "org.jetbrains.compose.material")
    }

    implementation(libs.intellij.util.text.matching)
    implementation(libs.intellij.util.base)
    implementation(libs.intellij.icons)

    implementation(fileTree(ghidraDistribution) {
        include("**/*.jar")
    })
}

compose.desktop {
    application {
        mainClass = "io.github.garyttierney.ghidralite.GhidraliteKt"
        jvmArgs("-Djava.system.class.loader=ghidra.GhidraClassLoader")
    }
}
