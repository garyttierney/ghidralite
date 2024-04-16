import java.io.FileReader
import java.util.*

plugins {
    `java-library`
}

val distSources = sourceSets.create("distribution") {
    resources {
        srcDirs("src/main/dist")
    }
}

open class GradleGhidraExtension(var installationDir: String = "<unknown>")

val ghidraExtension = project.extensions.create<GradleGhidraExtension>("ghidra")

val generateProperties = tasks.register<WriteProperties>("generateExtensionProperties") {
    destinationFile = project.layout.buildDirectory.file("dist/extension.properties")
    group = "distribution"

    doFirst {
        val ghidraProperties = Properties()
        ghidraProperties.load(FileReader("${ghidraExtension.installationDir}/Ghidra/application.properties"))

        property("name", project.name)
        property("createdOn", "now")
        property("description", "Extension description")
        property("version", ghidraProperties.getProperty("application.version"))
    }
}

val createZip = tasks.register<Zip>("assembleDist") {
    destinationDirectory = project.layout.buildDirectory.dir("dist")
    group = "distribution"

    into(project.name) {
        into("lib") {
            from(configurations.named("runtimeClasspath"))

            from(tasks.named("jar")) {
                filesMatching("*.jar") {
                    name = "${project.name}.jar"
                }
            }

            from(tasks.named("sourcesJar"))
        }

        from(distSources.output)
        from(generateProperties)
    }

    dependsOn(tasks.named("jar"), generateProperties)
}