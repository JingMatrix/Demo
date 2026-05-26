package org.matrix.demo

import androidx.appcompat.app.AppCompatActivity
import android.content.Context
import android.content.res.Configuration
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.telephony.TelephonyManager
import android.util.Log
import android.view.View
import android.widget.TextView
import android.widget.Toast
import java.lang.reflect.Modifier
import org.matrix.demo.databinding.ActivityMainBinding

const val TAG = "Demo"

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var doubleClick = false
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Example of a call to a native method
        binding.sampleText.text = stringFromJNI()

        binding.root.setOnClickListener {
            if (doubleClick) {
                // Double click
                binding.sampleText.text = stringFromJNI()
                Toast.makeText(this, "result updated", Toast.LENGTH_SHORT).show()
                doubleClick = false
            } else {
                // Single click
                doubleClick = true
                handler.postDelayed({
                    if (doubleClick) {
                        Toast.makeText(this, "double click to refresh result", Toast.LENGTH_SHORT).show()
                        doubleClick = false
                    }
                }, 200) // Double click time window
            }
        }

        val propertiesMap = getJavaRuntimeProperties()

        Log.d(TAG, "--- Listing ${propertiesMap.size} Java Runtime Properties ---")

        propertiesMap.toSortedMap().forEach { (key, value) ->
            Log.d(TAG, "[$key] = $value")
        }

        Log.d(TAG, "--- End of Properties ---")
        logAllConfigurationInfo(resources.configuration)

        val tm = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val carrierName = tm.getNetworkOperatorName()
        Log.d(TAG, "NetworkOperator: $carrierName")
    }

    /**
     * A native method that is implemented by the 'demo' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    companion object {
        // Used to load the 'demo' library on application startup.
        init {
            System.loadLibrary("demo")
        }
    }

    /**
     * Retrieves all Java runtime properties available on the Android device.
     * 
     * @return A Map containing property names as keys and property values as values.
     */
    fun getJavaRuntimeProperties(): Map<String, String> {
        val properties = System.getProperties()

        // stringPropertyNames() is the safest way to extract keys as strings
        return properties.stringPropertyNames().associateWith { key ->
            properties.getProperty(key) ?: ""
        }
    }
}

fun logAllConfigurationInfo(config: Configuration) {
    val clazz = Configuration::class.java

    Log.d(TAG, "=== Start of Configuration Info ===")

    // 1. Log all Public Fields
    Log.d(TAG, "--- Public Fields ---")
    clazz.fields.forEach { field ->
        try {
            // Only log instance fields (not static constants)
            if (!Modifier.isStatic(field.modifiers)) {
                val value = field.get(config)
                Log.d(TAG, "${field.name}: $value")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Could not access field ${field.name}")
        }
    }

    // 2. Log key Public Methods (Getters/Checkers)
    Log.d(TAG, "--- Public Methods ---")
    val methodsToLog = listOf(
        "getLayoutDirection",
        "getLocales",
        "isScreenRound",
        "isScreenWideColorGamut",
        "isScreenHdr"
    )

    methodsToLog.forEach { methodName ->
        try {
            val method = clazz.getMethod(methodName)
            val result = method.invoke(config)
            Log.d(TAG, "$methodName(): $result")
        } catch (e: NoSuchMethodException) {
            // Method might not exist on older API levels
        } catch (e: Exception) {
            Log.e(TAG, "Error calling $methodName: ${e.message}")
        }
    }

    // 3. Fallback: The built-in toString() is often very comprehensive
    Log.d(TAG, "--- Built-in Summary ---")
    Log.d(TAG, "toString(): $config")

    Log.d(TAG, "=== End of Configuration Info ===")
}
