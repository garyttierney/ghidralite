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

val ghidraDir = providers.gradleProperty("ghidra.dir")
    .getOrElse(rootDir.resolve("ghidra/build/dist/ghidra_11.0.3_DEV").absolutePath)

// TODO: is this the best way to do this?
System.setProperty("ghidra.dir", ghidraDir)

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

        ivy {
            url = uri(ghidraDir)

            metadataSources {
                gradleMetadata()
            }

            patternLayout {
                artifact("Ghidra/[artifact].[ext]")
                artifact("Ghidra/Configurations/[module]/lib/[artifact].[ext]")
                artifact("Ghidra/Features/[module]/lib/[artifact].[ext]")
                artifact("Ghidra/Framework/[module]/lib/[artifact].[ext]")
            }
        }
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
