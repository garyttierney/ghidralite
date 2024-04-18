plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
}

group = "io.github.garyttierney"
version = "unspecified"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation(kotlin("stdlib-jdk8"))
    implementation(libs.kotlinx.coroutines)
    implementation(libs.bundles.ghidra.all.modules)
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}