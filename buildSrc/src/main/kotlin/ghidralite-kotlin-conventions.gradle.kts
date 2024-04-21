@file:Suppress("UnstableApiUsage")

import org.jetbrains.gradle.ext.packagePrefix
import org.jetbrains.gradle.ext.settings
import kotlin.collections.set

val sarifReport: Provider<RegularFile> =
    layout.buildDirectory.file("reports/detekt-${project.name}.sarif")

plugins {
    id("ghidralite-conventions")
    id("ghidralite-linting-conventions")

    kotlin("jvm")
    kotlin("plugin.serialization")

    id("org.jetbrains.kotlinx.kover")
    id("io.gitlab.arturbosch.detekt")
}

java {
    withJavadocJar()
    withSourcesJar()
}

idea {
    module {
        settings {
            packagePrefix["src/main/kotlin"] = "${group}.${project.name.substringAfter("-").replace('-', '.')}"
        }
    }
}

detekt {
    // Failures are reported in GitHub
    ignoreFailures = true
}

koverReport {
    defaults {
        xml {
            onCheck = true
        }
    }
}

tasks {
    detektMain {
        reports {
            sarif {
                required = true
                outputLocation = sarifReport
            }
        }
    }
}

configurations.named("sarif") {
    outgoing {
        artifact(tasks.detektMain.flatMap { it.sarifReportFile }) { builtBy(tasks.detektMain) }
    }
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain {
        vendor = JvmVendorSpec.JETBRAINS
        languageVersion = JavaLanguageVersion.of(17)
    }
}