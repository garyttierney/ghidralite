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

open class GradleGhidraExtension(var path: File? = null)


val ghidraExtension = project.extensions.create<GradleGhidraExtension>("ghidra")
val ghidraProperties = Properties()

afterEvaluate {
    ghidraProperties.load(
        FileReader(
            ghidraExtension.path?.resolve("Ghidra/application.properties") ?: error("No Ghidra directory specified")
        )
    )
}

val generateProperties = tasks.register<WriteProperties>("generateExtensionProperties") {
    destinationFile = project.layout.buildDirectory.file("dist/extension.properties")
    group = "distribution"

    property("name", project.name)
    property("createdOn", "now")
    property("description", "Extension description")
    property("version", ghidraProperties.getProperty("application.version"))
}

val createZip = tasks.register<Zip>("assembleDist") {
    destinationDirectory = project.layout.buildDirectory.dir("dist")
    group = "distribution"

    val extensionName = project.name

    into(extensionName) {
        into("lib") {
            from(configurations.named("runtimeClasspath"))

            from(tasks.named("jar")) {
                filesMatching("*.jar") {
                    name = "$extensionName.jar"
                }
            }

            from(tasks.named("sourcesJar"))
        }

        from(distSources.output)
        from(generateProperties)
    }

    dependsOn(tasks.named("jar"), generateProperties)
}