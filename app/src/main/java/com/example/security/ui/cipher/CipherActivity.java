package com.example.security.ui.cipher;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

import com.example.security.R;
import com.example.security.base.AlgorithmType;
import com.example.security.base.CipherAlgorithm;
import com.example.security.databinding.ActivityCipherBinding;
import com.example.security.factory.CipherFactory;
import com.example.security.ui.base.BaseCipherActivity;
import com.example.security.utils.InputValidator;

public class CipherActivity extends BaseCipherActivity {

    public static final String EXTRA_ALGORITHM_TYPE = "extra_algorithm_type";

    private ActivityCipherBinding binding;
    private CipherAlgorithm       cipher;


    @Override
    protected void onCreate(Bundle savedInstanceState) {

        String typeName = getIntent().getStringExtra(EXTRA_ALGORITHM_TYPE);
        cipher = CipherFactory.create(AlgorithmType.valueOf(typeName));

        super.onCreate(savedInstanceState);

        setTitle(cipher.getAlgorithmName());
    }


    @Override
    protected void initViews() {

        binding = ActivityCipherBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        binding.etKey.setHint(cipher.getKeyHint());
        binding.etKey.setVisibility(cipher.requiresKey() ? View.VISIBLE : View.GONE);
    }

    @Override
    protected void setupListeners() {
        binding.btnEncrypt.setOnClickListener(v -> run(true));
        binding.btnDecrypt.setOnClickListener(v -> run(false));
    }


    private void run(boolean encrypt) {
        String text = binding.etInputText.getText().toString();
        String key  = binding.etKey.getText().toString();

        InputValidator.ValidationResult validation =
                InputValidator.validate(text, key, cipher.requiresKey());

        if (!validation.isValid()) {
            showError(validation.getErrorMessage());
            return;
        }

        try {
            String output = encrypt
                    ? cipher.encrypt(text, key)
                    : cipher.decrypt(text, key);
            binding.tvResult.setText(output);
        } catch (Exception e) {
            showError("Error: " + e.getMessage());
        }
    }
}