@file:Suppress("UnstableApiUsage")

import org.jetbrains.gradle.ext.settings

plugins {
    `ghidralite-conventions`
    idea
    alias(libs.plugins.qodana)
}

idea {
    project {
        settings {
            doNotDetectFrameworks("android", "web")
        }
    }
}