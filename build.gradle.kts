@file:Suppress("UnstableApiUsage")

import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    kotlin("jvm")
    alias(libs.plugins.ksp)
    alias(libs.plugins.kotlinx.serialization)
    alias(libs.plugins.composeDesktop)
}

repositories {
    google()
    gradlePluginPortal()
    mavenCentral()
    mavenLocal()

    // JetBrains repositories for compose-desktop and compose-multiplatform
    maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    maven("https://packages.jetbrains.team/maven/p/kpm/public/")

    // JetBrains repositories for IntelliJ components
    maven("https://www.jetbrains.com/intellij-repository/releases/")
    maven("https://cache-redirector.jetbrains.com/intellij-dependencies")
}

kotlin {
    jvmToolchain {
        vendor = JvmVendorSpec.JETBRAINS
        languageVersion = JavaLanguageVersion.of(17)
    }
}
val ghidraDistribution = extra["ghidra.dir"] as String

dependencies {
    implementation(project(":ghidra-schema-ksp"))
    ksp(project(":ghidra-schema-ksp"))

    implementation(libs.kotlin.reflect)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.filePicker)

    implementation(libs.jewel.standalone)
    implementation(libs.jewel.decorated.window)

    implementation(libs.jetbrains.compose.splitpane)
    implementation(compose.desktop.currentOs) {
        exclude(group = "org.jetbrains.compose.material")
    }

    implementation(libs.intellij.text.matching)

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
