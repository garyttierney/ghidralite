@file:Suppress("UnstableApiUsage")

import io.gitlab.arturbosch.detekt.report.ReportMergeTask
import org.jetbrains.gradle.ext.settings
import org.jetbrains.kotlin.gradle.utils.extendsFrom

plugins {
    `ghidralite-conventions`
    `ghidralite-linting-conventions`
    id("org.jetbrains.kotlinx.kover")
    id("io.gitlab.arturbosch.detekt")
    alias(libs.plugins.composeDesktop) apply(false)
}

idea {
    project {
        settings {
            doNotDetectFrameworks("android", "web")
        }
    }
}

val reports = configurations.register("reports") { isCanBeDeclared = true }

koverReport {
    defaults {
        xml {
            onCheck = true
        }
    }
}

configurations {
    kover.extendsFrom(reports)
    sarif.extendsFrom(reports)
}

dependencies {
    reports(project(":ghidralite-core"))
    reports(project(":ghidralite-core-ksp"))
    reports(project(":ghidralite-extension"))
    reports(project(":ghidralite-standalone"))
    reports(project(":ghidralite-ui"))
}

val projectSarifReport by tasks.registering(ReportMergeTask::class) {
    output.set(rootProject.layout.buildDirectory.file("reports/detekt/merge.sarif"))
    input.from(configurations.outgoingSarif)
}

task("check") {
    dependsOn(projectSarifReport)
}
