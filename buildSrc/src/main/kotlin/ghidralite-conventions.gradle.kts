plugins {
    idea
    id("org.jetbrains.gradle.plugin.idea-ext")
}

group = "io.github.garyttierney.ghidralite"
version = rootDir.resolve("version.txt").readText(Charsets.UTF_8)
