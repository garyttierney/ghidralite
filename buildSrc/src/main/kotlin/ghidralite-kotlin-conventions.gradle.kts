@file:Suppress("UnstableApiUsage")

import org.jetbrains.gradle.ext.*

plugins {
    kotlin("jvm")
    idea
    id("org.jetbrains.gradle.plugin.idea-ext")
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