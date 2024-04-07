@file:Suppress("UnstableApiUsage")

import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.compose")
}

repositories {
    google()
    mavenCentral()
    maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    maven("https://packages.jetbrains.team/maven/p/kpm/public/")
    maven("https://www.jetbrains.com/intellij-repository/releases/")
}
val ghidraInstallDir = extra["ghidra.dir"] as String

kotlin {
    jvm {
        jvmToolchain {
            vendor = JvmVendorSpec.JETBRAINS
            languageVersion = JavaLanguageVersion.of(17)
        }
    }

    sourceSets {
        val jvmMain by getting {
            dependencies {
                implementation(compose.desktop.currentOs) {
                    exclude(group = "org.jetbrains.compose.material")
                }
                implementation(fileTree(ghidraInstallDir) {
                    include("**/*.jar")
                    include("**/*-src.zip")
                })
                implementation("com.formdev:flatlaf:3.4.1")
                implementation("org.jetbrains.jewel:jewel-int-ui-standalone:${extra["jewel.version"] as String}")
                implementation("org.jetbrains.jewel:jewel-int-ui-decorated-window:${extra["jewel.version"] as String}")
                implementation("org.jetbrains.skiko:skiko-awt-runtime-macos-arm64:${extra["skiko.version"] as String}")
                implementation("org.jetbrains.compose.components:components-splitpane-desktop:${extra["compose.version"] as String}")
                implementation("com.fifesoft:rsyntaxtextarea:${extra["rsyntaxtextarea.version"] as String}")
                implementation("com.fifesoft:rstaui:${extra["rstaui.version"] as String}")
                implementation("net.java.dev.jna:jna:${extra["jna.version"] as String}")
                implementation("androidx.collection:collection:${extra["collections.version"] as String}")
            }
        }
    }
}

compose.desktop {
    application {
        mainClass = "GhidraliteKt"
        jvmArgs("-Djava.system.class.loader=ghidra.GhidraClassLoader")
        nativeDistributions {
            modules("jdk.unsupported")

            targetFormats(TargetFormat.Dmg)

            packageName = "Ghidralite"
            packageVersion = "1.0.0"
            description = "Ghidralite"
        }
    }
}
