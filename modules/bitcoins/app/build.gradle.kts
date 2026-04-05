plugins {
    scala
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Scala standard library - must match the _2.13 suffix used by bitcoin-s
    implementation("org.scala-lang:scala-library:2.13.12")

    // bitcoin-s core: BIP32 key derivation, PSBT, script parsing, transactions
    implementation("org.bitcoin-s:bitcoin-s-core_2.13:1.9.9")
}

// Use Java 21 toolchain, consistent with the rest of the project
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

application {
    mainClass.set("wrapper.Wrapper")
}
