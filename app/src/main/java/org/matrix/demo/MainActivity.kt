package org.matrix.demo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.Toast
import org.matrix.demo.databinding.ActivityMainBinding

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
}
