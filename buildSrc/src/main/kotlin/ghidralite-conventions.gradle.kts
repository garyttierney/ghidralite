@file:Suppress("UnstableApiUsage")

plugins {
    kotlin("jvm")
}

group = "io.github.garyttierney.ghidralite"
version = "0.1.0"

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