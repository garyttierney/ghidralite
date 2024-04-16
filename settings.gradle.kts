@file:Suppress("UnstableApiUsage")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

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
