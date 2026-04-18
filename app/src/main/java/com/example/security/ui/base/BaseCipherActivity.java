package com.example.security.ui.base;

import android.os.Bundle;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.annotation.LayoutRes;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.security.R;
import com.example.security.databinding.ActivityBaseCipherBinding;

public abstract class BaseCipherActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initViews();
        setupListeners();
    }

    protected abstract void initViews();

    protected abstract void setupListeners();


    protected void showError(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    protected void showSuccess(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }
}