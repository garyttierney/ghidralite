plugins {
    `ghidralite-conventions`
    id("me.champeau.jmh") version "0.7.2"
}

group = "io.github.garyttierney"
version = "unspecified"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}