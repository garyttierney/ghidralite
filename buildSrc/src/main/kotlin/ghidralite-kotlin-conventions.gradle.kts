@file:Suppress("UnstableApiUsage")


plugins {
    kotlin("jvm")
}

repositories {
    google()
    mavenCentral()

    // JetBrains repositories for compose-desktop and compose-multiplatform
    maven("https://maven.pkg.jetbrains.space/public/p/compose/dev")
    maven("https://packages.jetbrains.team/maven/p/kpm/public/")

    // JetBrains repositories for IntelliJ components
    maven("https://www.jetbrains.com/intellij-repository/releases/")
    maven("https://cache-redirector.jetbrains.com/intellij-dependencies")


    val ghidraDistribution = extra["ghidra.dir"] as String

    ivy {
        url = uri(ghidraDistribution)

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

java {
    withJavadocJar()
    withSourcesJar()
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