@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    }

    plugins {
        kotlin("jvm").version(extra["kotlin.version"] as String)
        id("org.jetbrains.compose").version(extra["compose.version"] as String)
    }
}

plugins {
    // Ensure JBR vendor is configured on CI, see https://github.com/actions/setup-java/issues/399.
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()

        // JetBrains repositories for compose-desktop and compose-multiplatform
        maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
        maven("https://packages.jetbrains.team/maven/p/kpm/public/")

        // JetBrains repositories for IntelliJ components
        maven("https://www.jetbrains.com/intellij-repository/releases/")
        maven("https://cache-redirector.jetbrains.com/intellij-dependencies")
    }

    versionCatalogs {
        create("libs") {
            from(files("versions.toml"))
        }
    }
}

rootProject.name = "ghidralite"

include("ghidralite-core")
include("ghidralite-core-ksp")
include("ghidralite-extension")
include("ghidralite-ui")
include("ghidralite-standalone")
includeBuild("ghidra")
include("ghidralite-platform")
