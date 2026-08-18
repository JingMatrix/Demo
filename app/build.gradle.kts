plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.matrix.demo"
    defaultConfig {
        applicationId = "org.matrix.demo"
        versionCode = 1
        versionName = "1.0"
        ndk {
            abiFilters += listOf("x86_64", "arm64-v8a")
        }
        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=c++_static"
                cppFlags += "-O2"
            }
        }
    }

    buildTypes {
        release {
            vcsInfo.include = false
            optimization {
                enable = true
                keepRules {
                    includeDefault = false
                }
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures {
        aidl = true
        buildConfig = true
        compose = true
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
    packaging {
        resources {
            excludes += "**"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }
    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
    dependenciesInfo {
        includeInApk = false
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.06.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
