plugins {
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
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}