plugins {
    kotlin("jvm") version "1.9.23"
}

group = "io.github.garyttierney"
version = "unspecified"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation(libs.ksp)
    implementation(kotlin("stdlib"))
}

sourceSets.main {
    java.srcDirs("src/main/kotlin")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}